package us.q3q.fido2;

/**
 * Encapsulates algorithm- and curve-specific sizing information for credentials.
 */
public final class CurveParameters {
    private final byte algorithmId;
    private final byte curveId;
    private final short keyLength;
    private final short publicKeyLength;
    private final short credentialPayloadLength;
    private final short credentialIdLength;

    private CurveParameters(byte algorithmId, byte curveId, short keyLength, short rpIdHashLength, short ivLength, short credentialRandomLength) {
        this.algorithmId = algorithmId;
        this.curveId = curveId;
        this.keyLength = keyLength;
        this.publicKeyLength = (short)(keyLength * 2 + 1);
        this.credentialPayloadLength = (short)(rpIdHashLength + keyLength + credentialRandomLength);
        this.credentialIdLength = (short)(this.credentialPayloadLength + ivLength + credentialRandomLength);
    }

    public static CurveParameters p256(short rpIdHashLength, short ivLength, short credentialRandomLength) {
        return new CurveParameters((byte) 0x26, (byte) 0x01, (short) 32, rpIdHashLength, ivLength, credentialRandomLength);
    }

    public byte getAlgorithmId() {
        return algorithmId;
    }

    public byte getCurveId() {
        return curveId;
    }

    public short getKeyLength() {
        return keyLength;
    }

    public short getPublicKeyLength() {
        return publicKeyLength;
    }

    public short getPublicKeyXYLength() {
        return (short)(publicKeyLength - 1);
    }

    public short getCredentialPayloadLength() {
        return credentialPayloadLength;
    }

    public short getCredentialIdLength() {
        return credentialIdLength;
    }
}
