package us.q3q.fido2;

/**
 * Represents the size-related parameters for a supported elliptic curve.
 */
public final class CurveParams {
    final short keyLength;
    final short keyBits;
    final short pubKeyLength;
    final short credentialPayloadLength;
    final short credentialIdLength;
    final short coseCurveId;
    final short coseAlgId;

    private static final short RP_HASH_LEN = 32;
    private static final short CREDENTIAL_IV_LEN = 16;
    private static final short CREDENTIAL_HMAC_LEN = 16;

    private static final CurveParams P256 = new CurveParams(
            (short) 32,
            (short) 256,
            (short) 65,
            (short) 1,
            (short) -7
    );
    private static final CurveParams P384 = new CurveParams(
            (short) 48,
            (short) 384,
            (short) 97,
            (short) 2,
            (short) -35
    );
    private static final CurveParams P521 = new CurveParams(
            (short) 66,
            (short) 521,
            (short) 133,
            (short) 3,
            (short) -36
    );

    private CurveParams(short keyLength, short keyBits, short pubKeyLength, short coseCurveId, short coseAlgId) {
        this.keyLength = keyLength;
        this.keyBits = keyBits;
        this.pubKeyLength = pubKeyLength;
        this.credentialPayloadLength = (short) (RP_HASH_LEN + keyLength + CREDENTIAL_HMAC_LEN);
        this.credentialIdLength = (short) (credentialPayloadLength + CREDENTIAL_IV_LEN + CREDENTIAL_HMAC_LEN);
        this.coseCurveId = coseCurveId;
        this.coseAlgId = coseAlgId;
    }

    static CurveParams forAlgorithm(short alg) {
        if (alg == P256.coseAlgId) {
            return P256;
        }
        if (alg == P384.coseAlgId) {
            return P384;
        }
        if (alg == P521.coseAlgId) {
            return P521;
        }
        return null;
    }

    short getKeyLength() {
        return keyLength;
    }

    short getPubKeyLength() {
        return pubKeyLength;
    }

    short getCredentialPayloadLength() {
        return credentialPayloadLength;
    }

    short getCredentialIdLength() {
        return credentialIdLength;
    }

    short getCoseCurveId() {
        return coseCurveId;
    }

    short getCoseAlgId() {
        return coseAlgId;
    }

    static CurveParams forKeyLength(short keyLen) {
        if (keyLen == P256.keyLength) {
            return P256;
        }
        if (keyLen == P384.keyLength) {
            return P384;
        }
        if (keyLen == P521.keyLength) {
            return P521;
        }
        return null;
    }

    static CurveParams forCredentialIdLength(short credLen) {
        if (credLen == P256.credentialIdLength) {
            return P256;
        }
        if (credLen == P384.credentialIdLength) {
            return P384;
        }
        if (credLen == P521.credentialIdLength) {
            return P521;
        }
        return null;
    }

    static short getMaxCredentialIdLength() {
        short max = P256.credentialIdLength;
        if (P384.credentialIdLength > max) {
            max = P384.credentialIdLength;
        }
        if (P521.credentialIdLength > max) {
            max = P521.credentialIdLength;
        }
        return max;
    }

    static short getMaxCredentialPayloadLength() {
        short max = P256.credentialPayloadLength;
        if (P384.credentialPayloadLength > max) {
            max = P384.credentialPayloadLength;
        }
        if (P521.credentialPayloadLength > max) {
            max = P521.credentialPayloadLength;
        }
        return max;
    }
}
