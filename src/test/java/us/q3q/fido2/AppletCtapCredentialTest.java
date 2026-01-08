package us.q3q.fido2;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AppletCtapCredentialTest {
    private static final short ALG_ES256 = -7;
    private static final short ALG_ES384 = -35;
    private static final short ALG_ES512 = -36;

    private CardSimulator simulator;
    private final AID appletAID = AIDUtil.create("A0000006472F0001");

    @BeforeEach
    public void setupApplet() {
        simulator = new CardSimulator();
        simulator.installApplet(appletAID, FIDO2Applet.class);
        simulator.selectApplet(appletAID);
    }

    @Test
    public void getInfoAdvertisesAllAlgorithms() {
        ResponseAPDU response = sendCTAP(new byte[] {FIDOConstants.CMD_GET_INFO});
        assertEquals(ISO7816.SW_NO_ERROR, response.getSW());

        byte[] data = response.getData();
        assertEquals(FIDOConstants.CTAP2_OK, data[0]);

        CborReader reader = new CborReader(data, 1);
        Map<Object, Object> map = reader.readMap();
        Object algorithmsObj = map.get(10);
        assertNotNull(algorithmsObj);
        assertTrue(algorithmsObj instanceof List);
        List<?> algorithms = (List<?>) algorithmsObj;
        List<Integer> algIds = new ArrayList<>();
        for (Object entry : algorithms) {
            assertTrue(entry instanceof Map);
            Map<?, ?> algMap = (Map<?, ?>) entry;
            Object algVal = algMap.get("alg");
            assertTrue(algVal instanceof Integer);
            algIds.add((Integer) algVal);
        }

        assertTrue(algIds.contains((int) ALG_ES256));
        assertTrue(algIds.contains((int) ALG_ES384));
        assertTrue(algIds.contains((int) ALG_ES512));
    }

    @Test
    public void residentKeysRoundTripPerCurveAndAttestationMatches() throws Exception {
        String rpId = "example.com";
        Map<Short, PublicKey> publicKeys = new HashMap<>();

        short[] algs = new short[] {ALG_ES256, ALG_ES384, ALG_ES512};
        for (short alg : algs) {
            byte[] clientDataHash = buildClientDataHash(hashLengthForAlg(alg));
            byte[] userId = buildUserIdForAlg(alg);
            String userName = "user-" + alg;
            byte[] request = buildMakeCredentialRequest(rpId, "Example", userId, userName, clientDataHash, alg, true);

            ResponseAPDU response = sendCTAP(request);
            assertEquals(ISO7816.SW_NO_ERROR, response.getSW());

            byte[] data = response.getData();
            assertEquals(FIDOConstants.CTAP2_OK, data[0]);
            CborReader reader = new CborReader(data, 1);
            Map<Object, Object> responseMap = reader.readMap();
            byte[] authData = (byte[]) responseMap.get(2);
            Map<?, ?> attStmt = (Map<?, ?>) responseMap.get(3);
            assertNotNull(attStmt);
            Object algValue = attStmt.get("alg");
            assertEquals(alg, ((Integer) algValue).shortValue());
            byte[] signature = (byte[]) attStmt.get("sig");

            CoseKey coseKey = extractCoseKey(authData);
            assertEquals(alg, coseKey.alg);
            PublicKey publicKey = buildPublicKey(coseKey, alg);
            assertTrue(verifySignature(alg, publicKey, authData, clientDataHash, signature));

            publicKeys.put(alg, publicKey);
        }

        for (short alg : algs) {
            byte[] clientDataHash = buildClientDataHash(hashLengthForAlg(alg));
            byte[] request = buildGetAssertionRequest(rpId, clientDataHash, alg);
            ResponseAPDU response = sendCTAP(request);
            assertEquals(ISO7816.SW_NO_ERROR, response.getSW());

            byte[] data = response.getData();
            assertEquals(FIDOConstants.CTAP2_OK, data[0]);
            CborReader reader = new CborReader(data, 1);
            Map<Object, Object> responseMap = reader.readMap();
            byte[] authData = (byte[]) responseMap.get(2);
            byte[] signature = (byte[]) responseMap.get(3);
            PublicKey publicKey = publicKeys.get(alg);
            assertNotNull(publicKey);
            assertTrue(verifySignature(alg, publicKey, authData, clientDataHash, signature));
        }
    }

    @Test
    public void getAssertionFailsOnAlgMismatch() {
        String rpId = "example.com";
        byte[] clientDataHash = buildClientDataHash(hashLengthForAlg(ALG_ES256));
        byte[] userId = buildUserIdForAlg(ALG_ES256);
        byte[] makeRequest = buildMakeCredentialRequest(rpId, "Example", userId, "user", clientDataHash, ALG_ES256, true);
        ResponseAPDU makeResponse = sendCTAP(makeRequest);
        assertEquals(ISO7816.SW_NO_ERROR, makeResponse.getSW());
        assertEquals(FIDOConstants.CTAP2_OK, makeResponse.getData()[0]);

        byte[] mismatchClientHash = buildClientDataHash(hashLengthForAlg(ALG_ES384));
        byte[] assertion = buildGetAssertionRequest(rpId, mismatchClientHash, ALG_ES384);
        ResponseAPDU response = sendCTAP(assertion);
        assertEquals(ISO7816.SW_NO_ERROR, response.getSW());
        assertEquals(FIDOConstants.CTAP2_ERR_UNSUPPORTED_ALGORITHM, response.getData()[0]);
    }

    private ResponseAPDU sendCTAP(byte[] command) {
        int[] framedVals = new int[command.length + 6];
        framedVals[0] = 0x80;
        framedVals[1] = 0x10;
        framedVals[2] = 0x00;
        framedVals[3] = 0x00;
        framedVals[4] = command.length;
        for (int i = 0; i < command.length; i++) {
            framedVals[i + 5] = command[i] & 0xFF;
        }
        framedVals[framedVals.length - 1] = 0x00;
        return send(framedVals);
    }

    private ResponseAPDU send(int... params) {
        byte[] bparams = new byte[params.length];
        for (int i = 0; i < params.length; i++) {
            bparams[i] = (byte) params[i];
        }

        CommandAPDU commandAPDU = new CommandAPDU(bparams);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);

        ArrayList<ResponseAPDU> prevResponses = new ArrayList<>();
        int totalResponseLen = response.getNr();
        prevResponses.add(response);
        while (response.getSW() >= ISO7816.SW_BYTES_REMAINING_00
                && response.getSW() < ISO7816.SW_BYTES_REMAINING_00 + 256
                && totalResponseLen < 65537) {
            CommandAPDU nextAPDU = new CommandAPDU(new byte[] {0x00, (byte) 0xC0, 0x00, 0x00});
            response = simulator.transmitCommand(nextAPDU);
            prevResponses.add(response);
            totalResponseLen += response.getData().length;
        }

        byte[] combined = new byte[totalResponseLen + 2];
        ResponseAPDU lastResponse = prevResponses.get(prevResponses.size() - 1);

        int off = 0;
        for (ResponseAPDU resp : prevResponses) {
            byte[] b = resp.getData();
            System.arraycopy(b, 0, combined, off, b.length);
            off += b.length;
        }

        combined[off++] = (byte) lastResponse.getSW1();
        combined[off] = (byte) lastResponse.getSW2();

        return new ResponseAPDU(combined);
    }

    private static byte[] buildMakeCredentialRequest(String rpId, String rpName, byte[] userId, String userName,
                                                     byte[] clientDataHash, short alg, boolean rk) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(FIDOConstants.CMD_MAKE_CREDENTIAL);
        writeMapStart(out, rk ? 5 : 4);

        out.write(0x01);
        writeBytes(out, clientDataHash);

        out.write(0x02);
        writeMapStart(out, 2);
        writeText(out, "id");
        writeText(out, rpId);
        writeText(out, "name");
        writeText(out, rpName);

        out.write(0x03);
        writeMapStart(out, 2);
        writeText(out, "id");
        writeBytes(out, userId);
        writeText(out, "name");
        writeText(out, userName);

        out.write(0x04);
        writeArrayStart(out, 1);
        writeMapStart(out, 2);
        writeText(out, "alg");
        writeInt(out, alg);
        writeText(out, "type");
        writeText(out, "public-key");

        if (rk) {
            out.write(0x07);
            writeMapStart(out, 1);
            writeText(out, "rk");
            out.write(0xF5);
        }

        return out.toByteArray();
    }

    private static byte[] buildGetAssertionRequest(String rpId, byte[] clientDataHash, short alg) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(FIDOConstants.CMD_GET_ASSERTION);
        writeMapStart(out, 3);

        out.write(0x01);
        writeText(out, rpId);

        out.write(0x02);
        writeBytes(out, clientDataHash);

        out.write(0x08);
        writeInt(out, alg);

        return out.toByteArray();
    }

    private static byte[] buildClientDataHash(int length) {
        byte[] data = new byte[length];
        for (int i = 0; i < length; i++) {
            data[i] = (byte) (i + 1);
        }
        return data;
    }

    private static byte[] buildUserIdForAlg(short alg) {
        byte[] id = new byte[16];
        for (int i = 0; i < id.length; i++) {
            id[i] = (byte) (alg + i);
        }
        return id;
    }

    private static int hashLengthForAlg(short alg) {
        if (alg == ALG_ES256) {
            return 32;
        }
        if (alg == ALG_ES384) {
            return 48;
        }
        return 64;
    }

    private static void writeMapStart(ByteArrayOutputStream out, int size) {
        out.write(0xA0 + size);
    }

    private static void writeArrayStart(ByteArrayOutputStream out, int size) {
        out.write(0x80 + size);
    }

    private static void writeText(ByteArrayOutputStream out, String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        writeMajorTypeLength(out, 3, bytes.length);
        out.write(bytes, 0, bytes.length);
    }

    private static void writeBytes(ByteArrayOutputStream out, byte[] bytes) {
        writeMajorTypeLength(out, 2, bytes.length);
        out.write(bytes, 0, bytes.length);
    }

    private static void writeInt(ByteArrayOutputStream out, int value) {
        if (value >= 0) {
            writeUnsigned(out, value);
            return;
        }
        int negValue = -1 - value;
        if (negValue < 24) {
            out.write(0x20 + negValue);
        } else if (negValue < 256) {
            out.write(0x38);
            out.write(negValue);
        } else {
            out.write(0x39);
            out.write((negValue >> 8) & 0xFF);
            out.write(negValue & 0xFF);
        }
    }

    private static void writeUnsigned(ByteArrayOutputStream out, int value) {
        if (value < 24) {
            out.write(value);
        } else if (value < 256) {
            out.write(0x18);
            out.write(value);
        } else {
            out.write(0x19);
            out.write((value >> 8) & 0xFF);
            out.write(value & 0xFF);
        }
    }

    private static void writeMajorTypeLength(ByteArrayOutputStream out, int majorType, int length) {
        if (length < 24) {
            out.write((majorType << 5) | length);
        } else if (length < 256) {
            out.write((majorType << 5) | 24);
            out.write(length);
        } else {
            out.write((majorType << 5) | 25);
            out.write((length >> 8) & 0xFF);
            out.write(length & 0xFF);
        }
    }

    private static CoseKey extractCoseKey(byte[] authData) {
        int offset = 32 + 1 + 4 + 16;
        int credIdLen = ((authData[offset] & 0xFF) << 8) | (authData[offset + 1] & 0xFF);
        offset += 2 + credIdLen;
        CborReader reader = new CborReader(authData, offset);
        Map<Object, Object> cose = reader.readMap();
        byte[] x = (byte[]) cose.get(-2);
        byte[] y = (byte[]) cose.get(-3);
        int alg = (int) cose.get(3);
        return new CoseKey(alg, x, y);
    }

    private static PublicKey buildPublicKey(CoseKey coseKey, short alg) throws Exception {
        String curve = curveNameForAlg(alg);
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(curve));
        ECParameterSpec ecSpec = parameters.getParameterSpec(ECParameterSpec.class);
        ECPoint point = new ECPoint(new java.math.BigInteger(1, coseKey.x), new java.math.BigInteger(1, coseKey.y));
        ECPublicKeySpec keySpec = new ECPublicKeySpec(point, ecSpec);
        return KeyFactory.getInstance("EC").generatePublic(keySpec);
    }

    private static boolean verifySignature(short alg, PublicKey publicKey, byte[] authData,
                                           byte[] clientDataHash, byte[] signature) throws Exception {
        String algorithm = signatureAlgorithmForAlg(alg);
        Signature verifier = Signature.getInstance(algorithm);
        verifier.initVerify(publicKey);
        verifier.update(authData);
        verifier.update(clientDataHash);
        return verifier.verify(signature);
    }

    private static String curveNameForAlg(short alg) {
        if (alg == ALG_ES256) {
            return "secp256r1";
        }
        if (alg == ALG_ES384) {
            return "secp384r1";
        }
        return "secp521r1";
    }

    private static String signatureAlgorithmForAlg(short alg) {
        if (alg == ALG_ES256) {
            return "SHA256withECDSA";
        }
        if (alg == ALG_ES384) {
            return "SHA384withECDSA";
        }
        return "SHA512withECDSA";
    }

    private static class CoseKey {
        private final short alg;
        private final byte[] x;
        private final byte[] y;

        private CoseKey(int alg, byte[] x, byte[] y) {
            this.alg = (short) alg;
            this.x = x;
            this.y = y;
        }
    }

    private static class CborReader {
        private final byte[] data;
        private int index;

        private CborReader(byte[] data, int offset) {
            this.data = data;
            this.index = offset;
        }

        private Map<Object, Object> readMap() {
            int initial = readByte();
            int major = initial >> 5;
            int addl = initial & 0x1F;
            if (major != 5) {
                throw new IllegalStateException("Expected map");
            }
            int length = readLength(addl);
            Map<Object, Object> map = new LinkedHashMap<>();
            for (int i = 0; i < length; i++) {
                Object key = readObject();
                Object value = readObject();
                map.put(key, value);
            }
            return map;
        }

        private Object readObject() {
            int initial = readByte();
            int major = initial >> 5;
            int addl = initial & 0x1F;
            switch (major) {
                case 0:
                    return readLength(addl);
                case 1:
                    return -1 - readLength(addl);
                case 2:
                    return readBytes(addl);
                case 3:
                    return readText(addl);
                case 4:
                    return readArray(addl);
                case 5:
                    index--;
                    return readMap();
                case 7:
                    if (addl == 20) {
                        return Boolean.FALSE;
                    }
                    if (addl == 21) {
                        return Boolean.TRUE;
                    }
                    return null;
                default:
                    throw new IllegalStateException("Unsupported CBOR major type: " + major);
            }
        }

        private List<Object> readArray(int addl) {
            int length = readLength(addl);
            List<Object> values = new ArrayList<>();
            for (int i = 0; i < length; i++) {
                values.add(readObject());
            }
            return values;
        }

        private byte[] readBytes(int addl) {
            int length = readLength(addl);
            byte[] result = new byte[length];
            System.arraycopy(data, index, result, 0, length);
            index += length;
            return result;
        }

        private String readText(int addl) {
            int length = readLength(addl);
            String text = new String(data, index, length, StandardCharsets.UTF_8);
            index += length;
            return text;
        }

        private int readLength(int addl) {
            if (addl < 24) {
                return addl;
            }
            if (addl == 24) {
                return readByte();
            }
            if (addl == 25) {
                return (readByte() << 8) | readByte();
            }
            throw new IllegalStateException("Unsupported length encoding: " + addl);
        }

        private int readByte() {
            return data[index++] & 0xFF;
        }
    }
}
