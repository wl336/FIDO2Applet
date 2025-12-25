package us.q3q.fido2;

import javacard.security.ECKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

/**
 * Encapsulates per-curve parameters and metadata, keyed by COSE algorithm identifiers.
 */
public final class CurveParameters {
    public static final short COSE_ALG_ES256 = -7;
    public static final short COSE_ALG_ES384 = -35;
    public static final short COSE_ALG_ES512 = -36;

    public static final byte COSE_CURVE_P256 = 0x01;
    public static final byte COSE_CURVE_P384 = 0x02;
    public static final byte COSE_CURVE_P521 = 0x03;

    private static final short RP_HASH_LEN = 32;
    private static final short CREDENTIAL_RANDOM_LEN = 16;
    private static final short CREDENTIAL_IV_LEN = 16;

    private interface CurveSetter {
        void setCurve(ECKey key);
    }

    private static final CurveParameters[] SUPPORTED = {
            new CurveParameters(COSE_ALG_ES256, COSE_CURVE_P256, (short) 32,
                    KeyBuilder.LENGTH_EC_FP_256, Signature.ALG_ECDSA_SHA_256,
                    new CurveSetter() {
                        public void setCurve(ECKey key) {
                            P256Constants.setCurve(key);
                        }
                    }),
            new CurveParameters(COSE_ALG_ES384, COSE_CURVE_P384, (short) 48,
                    KeyBuilder.LENGTH_EC_FP_384, Signature.ALG_ECDSA_SHA_384,
                    new CurveSetter() {
                        public void setCurve(ECKey key) {
                            P384Constants.setCurve(key);
                        }
                    }),
            new CurveParameters(COSE_ALG_ES512, COSE_CURVE_P521, (short) 66,
                    KeyBuilder.LENGTH_EC_FP_521, Signature.ALG_ECDSA_SHA_512,
                    new CurveSetter() {
                        public void setCurve(ECKey key) {
                            P521Constants.setCurve(key);
                        }
                    })
    };

    public static final short MAX_POINT_LENGTH;
    public static final short MAX_PUBLIC_KEY_LENGTH;
    public static final short MAX_CREDENTIAL_ID_LEN;

    static {
        short maxPoint = 0;
        short maxPub = 0;
        short maxCredentialId = 0;
        for (short i = 0; i < SUPPORTED.length; i++) {
            final CurveParameters params = SUPPORTED[i];
            if (params.pointLength > maxPoint) {
                maxPoint = params.pointLength;
            }
            if (params.publicKeyLength > maxPub) {
                maxPub = params.publicKeyLength;
            }
            if (params.credentialIdLength > maxCredentialId) {
                maxCredentialId = params.credentialIdLength;
            }
        }
        MAX_POINT_LENGTH = maxPoint;
        MAX_PUBLIC_KEY_LENGTH = maxPub;
        MAX_CREDENTIAL_ID_LEN = maxCredentialId;
    }

    public static CurveParameters forAlg(short coseAlgId) {
        for (short i = 0; i < SUPPORTED.length; i++) {
            if (SUPPORTED[i].coseAlgId == coseAlgId) {
                return SUPPORTED[i];
            }
        }
        return null;
    }

    public static CurveParameters forCurve(byte coseCurveId) {
        for (short i = 0; i < SUPPORTED.length; i++) {
            if (SUPPORTED[i].coseCurveId == coseCurveId) {
                return SUPPORTED[i];
            }
        }
        return null;
    }

    private final short coseAlgId;
    private final byte coseCurveId;
    private final short pointLength;
    private final short publicKeyLength;
    private final short credentialPayloadLength;
    private final short credentialIdLength;
    private final short keyBuilderLength;
    private final byte signatureAlgorithm;
    private final CurveSetter setter;

    private CurveParameters(short coseAlgId, byte coseCurveId, short pointLength, short keyBuilderLength,
                            byte signatureAlgorithm, CurveSetter setter) {
        this.coseAlgId = coseAlgId;
        this.coseCurveId = coseCurveId;
        this.pointLength = pointLength;
        this.publicKeyLength = (short) (2 * pointLength + 1);
        this.credentialPayloadLength = (short) (RP_HASH_LEN + pointLength + CREDENTIAL_RANDOM_LEN);
        this.credentialIdLength = (short) (credentialPayloadLength + CREDENTIAL_IV_LEN + CREDENTIAL_RANDOM_LEN);
        this.keyBuilderLength = keyBuilderLength;
        this.signatureAlgorithm = signatureAlgorithm;
        this.setter = setter;
    }

    public short getCoseAlgId() {
        return coseAlgId;
    }

    public byte getCoseCurveId() {
        return coseCurveId;
    }

    public short getPointLength() {
        return pointLength;
    }

    public short getPublicKeyLength() {
        return publicKeyLength;
    }

    public short getCredentialPayloadLength() {
        return credentialPayloadLength;
    }

    public short getCredentialIdLength() {
        return credentialIdLength;
    }

    public short getKeyBuilderLength() {
        return keyBuilderLength;
    }

    public byte getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void applyTo(ECKey key) {
        setter.setCurve(key);
    }
}
