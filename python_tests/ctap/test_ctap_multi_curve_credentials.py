import copy
import secrets

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fido2.cose import ES256, ES384, ES512
from fido2.ctap import CtapError

from .ctap_test import CTAPTestCase


class CTAPMultiCurveCredentialTestCase(CTAPTestCase):
    ALG_DETAILS = {
        ES256.ALGORITHM: 32,
        ES384.ALGORITHM: 48,
        ES512.ALGORITHM: 66,
    }
    TARGET_ALGS = (ES256.ALGORITHM, ES384.ALGORITHM, ES512.ALGORITHM)

    def setUp(self, install_params: bytes | None = None) -> None:
        super().setUp(install_params)
        self.supported_algorithms = {entry["alg"] for entry in self.ctap2.get_info().algorithms}

    def _require_algorithm(self, alg: int) -> None:
        if alg not in self.supported_algorithms:
            self.skipTest(f"Authenticator does not advertise algorithm {alg}")

    def _assert_signature_shape(self, pub_key, signature: bytes, coordinate_length: int) -> None:
        self.assertEqual(coordinate_length, len(pub_key[-2]))
        self.assertEqual(coordinate_length, len(pub_key[-3]))
        r, s = decode_dss_signature(signature)
        self.assertLessEqual((r.bit_length() + 7) // 8, coordinate_length)
        self.assertLessEqual((s.bit_length() + 7) // 8, coordinate_length)

    def _build_makecred_params(self, alg: int, resident: bool = False, user_overrides: dict | None = None) -> dict:
        params = copy.deepcopy(self.basic_makecred_params)
        params["key_params"] = [{"type": "public-key", "alg": alg}]
        params.pop("options", None)
        if resident:
            params["options"] = {"rk": True}
        if user_overrides:
            params["user"].update(user_overrides)
        return params

    def test_make_credential_and_assertion_by_curve(self):
        for alg in self.TARGET_ALGS:
            with self.subTest(algorithm=alg):
                self._require_algorithm(alg)
                credential = self.ctap2.make_credential(**self._build_makecred_params(alg))
                self.assertEqual(alg, credential.att_stmt["alg"])

                pub_key = credential.auth_data.credential_data.public_key
                coord_len = self.ALG_DETAILS[alg]
                self._assert_signature_shape(pub_key, credential.att_stmt["sig"], coord_len)
                pub_key.verify(credential.auth_data + self.client_data, credential.att_stmt["sig"])

                assertion_client_data = self.get_random_client_data()
                assertion = self.get_assertion_from_cred(credential, client_data=assertion_client_data)
                self.assertEqual(credential.auth_data.credential_data.credential_id, assertion.credential["id"])
                pub_key.verify(assertion.auth_data + assertion_client_data, assertion.signature)
                self._assert_signature_shape(pub_key, assertion.signature, coord_len)

    def test_resident_key_storage_and_allow_list_across_curves(self):
        algs = [a for a in self.TARGET_ALGS if a in self.supported_algorithms]
        if not algs:
            self.skipTest("Authenticator does not advertise any ES algorithm support")

        credentials = []
        for alg in algs:
            user_id = secrets.token_bytes(24)
            params = self._build_makecred_params(
                alg,
                resident=True,
                user_overrides={
                    "id": user_id,
                    "name": secrets.token_hex(10),
                },
            )
            cred = self.ctap2.make_credential(**params)
            credentials.append((alg, cred, user_id))

        for alg, cred, user_id in credentials:
            client_data = self.get_random_client_data()
            assertion = self.ctap2.get_assertion(
                rp_id=self.rp_id,
                client_data_hash=client_data,
                allow_list=[
                    {
                        "type": "public-key",
                        "id": cred.auth_data.credential_data.credential_id,
                    }
                ],
            )
            self.assertEqual(user_id, assertion.user["id"])
            pub_key = cred.auth_data.credential_data.public_key
            self._assert_signature_shape(pub_key, assertion.signature, self.ALG_DETAILS[alg])
            pub_key.verify(assertion.auth_data + client_data, assertion.signature)
            if assertion.number_of_credentials is not None:
                self.assertEqual(1, assertion.number_of_credentials)

        if len(credentials) < 2:
            return

        allow_list = [
            {"type": "public-key", "id": cred.auth_data.credential_data.credential_id}
            for _, cred, _ in credentials
        ]
        mixed_client_data = self.get_random_client_data()
        assertions = [
            self.ctap2.get_assertion(
                rp_id=self.rp_id,
                client_data_hash=mixed_client_data,
                allow_list=allow_list,
            )
        ]
        for _ in range(len(credentials) - 1):
            assertions.append(self.ctap2.get_next_assertion())

        credential_lookup = {
            cred.auth_data.credential_data.credential_id: (alg, cred, user_id)
            for alg, cred, user_id in credentials
        }
        self.assertSetEqual(set(credential_lookup.keys()), {a.credential["id"] for a in assertions})

        for assertion in assertions:
            alg, cred, user_id = credential_lookup[assertion.credential["id"]]
            pub_key = cred.auth_data.credential_data.public_key
            self._assert_signature_shape(pub_key, assertion.signature, self.ALG_DETAILS[alg])
            pub_key.verify(assertion.auth_data + mixed_client_data, assertion.signature)
            self.assertEqual(user_id, assertion.user["id"])
            if assertion.number_of_credentials is not None:
                self.assertEqual(len(credentials), assertion.number_of_credentials)

        with self.assertRaises(CtapError) as err:
            self.ctap2.get_next_assertion()
        self.assertEqual(CtapError.ERR.NO_CREDENTIALS, err.exception.code)
