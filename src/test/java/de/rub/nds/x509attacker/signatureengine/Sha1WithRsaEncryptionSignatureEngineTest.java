package de.rub.nds.x509attacker.signatureengine;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.security.Security;

import static org.junit.Assert.*;

public class Sha1WithRsaEncryptionSignatureEngineTest {

    @Test
    public void testInvocation() {
        Security.addProvider(new BouncyCastleProvider());
        SignatureEngine signatureEngine = null;
        try {
            signatureEngine = SignatureEngine.getInstance(Sha1WithRsaEncryptionSignatureEngine.objectIdentifierString);
        } catch (SignatureEngineException e) {
            e.printStackTrace();
        }
        assertNotEquals(null, signatureEngine);
    }

    @Test
    public void testParsePemKey() {
        Security.addProvider(new BouncyCastleProvider());
        SignatureEngine signatureEngine = null;
        String pemFileContent = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIIEpAIBAAKCAQEAvNSgc3qE5HHUFjqk01s5P7kvj/U1vp5hUCQuu/VbiU7eSIaW\n" +
                "MjBnMzx34iopdTtCwUqHumhODjJXXZfA44nECEPO3BGiIYTBTJteTcyYpFPXeweh\n" +
                "msKLXYhHA21nCadm97DmpWy/jNP05oDaDL5f42eMH0JOCGOt6FIeNEqosUG90IKO\n" +
                "QdHKap5lKX5daoVYsYW3Wr13NtZyTVZa8KPs5wRmn8FjL9cws4EewbqmSGDuXTia\n" +
                "qpJHpnBP17qd/8kbLcNnxFN1v33yNhPBJOWA9ZWyzp3zqcS8nQHWFKM2gc49aqTY\n" +
                "qKcfFpbrnvQvL69GsYKA6gHXlH+tc82CMBdt7wIDAQABAoIBABGLS9EO3BQBg2wB\n" +
                "TNkaS6phAUtFxBWOz4nLos/xzuxl+H8SihflqWD4SEcqFan/tIcS7qNiF4Z4JOfc\n" +
                "Np6taRo/epO1y7ODixYcBVoDHVd/NrEGl3wygRJSnA50drNN62It/G/4N5/U/ZcA\n" +
                "98FhWrVdJIau+WMMJ9dC8e131k6JnOqdAPJgKoTlAdxX2AlWKHZIbKqhmV7kspi5\n" +
                "j88/+54Haq4w9FCuopTJOMu4EnYzWfwwU1IAs79uXyuDZSJkz+Zpe8uBC1p9uSXV\n" +
                "U90ItjtxQ0VjLe8filHQQbIDUD3eSe44O3PiS6aJGQBJEJDDxVjPhStB5iNFTH6n\n" +
                "o3rPpPkCgYEA+x05TFrRzBDCOcGOKvgz1yweiTFibOoZ0GB7/Du9hpAg6GoW1KoP\n" +
                "CGGiNhvTJvx5Hvi+cYllIshY/2nymhXcGDSudllyjPJpzi91DIzguUMF/jSoqwaS\n" +
                "WFVlOKYWagR2PmwTWys9wtTCEp7X9RHOOBU28dQ5TNZ38ab9S5pnA20CgYEAwIEs\n" +
                "mkLGcOpsg3ivDnM8MtcOLWcFhk5U5EsbWJOGzKvwtOyRmpqt6V0awOt9tZrJPK6A\n" +
                "fN2R+UNo5PjAdl0gP+0Kl3zr+QHW5jL/VURe83/2eH6cebBg32is6AE83UHUnryN\n" +
                "zd8Lysud9X1Pxy2hkUF84FJSjXfMzJPBXcq+AUsCgYEA5+zgy82hsRjVWiSTWsps\n" +
                "jtIXzdxHrJI2j0ddm+PNMugRDLdXKMl8IuCRwenHBl3uvBU/R3t/ZjWmRRgkUf3Y\n" +
                "jp6xd2s7qkQGRsF8GMBQmar2cQdPtM3YAi+00jJLx1UhpJuK8Qwp+bUpHauJh7YP\n" +
                "QasOWSIKXhZDJ3R0wwvzEq0CgYEAjbrNFuoQ5jOCHy2sXQw0hw3Ur1LJO3/Sep5d\n" +
                "jNJZDbmNp/cAoH4/iq/0sZLv49QJUzb6/HO5NHcP9Hy8XqjjxI0GHlBn/9X93VAw\n" +
                "sxt6ePZ+hWpaVDGqsPGFU+8NW61LGG+kS61rJizRqFtRcEjFSoeXpCSYCPXp/7jN\n" +
                "Rfut9o8CgYA0/sbL9yOZdmcveh0bMl69hRHDb4jgTwm5rF7DKb5wjeHyd+SmN6BJ\n" +
                "dtBWFYAFvB5OWwjR0aqe3lmc/FCXIn1HL43OqgcDMZATfOA2nhFxtQPbfJMmTgPK\n" +
                "Qwkhq2kEFTTv8ifpqEfha+l+HiT/btsS78LkfgUVDkr8esC0PNzyQg==\n" +
                "-----END RSA PRIVATE KEY-----";
        boolean success = false;
        try {
            signatureEngine = SignatureEngine.getInstance(Sha1WithRsaEncryptionSignatureEngine.objectIdentifierString);
        } catch (SignatureEngineException e) {
            e.printStackTrace();
        }
        try {
            signatureEngine.init(pemFileContent.getBytes(), SignatureEngine.KeyType.PEM_ENCODED, null);
            success = true;
        } catch (SignatureEngineException e) {
            e.printStackTrace();
        }
        assertEquals(true, success);
    }

    @Test
    public void testSign() {
        Security.addProvider(new BouncyCastleProvider());
        SignatureEngine signatureEngine = null;
        String pemFileContent = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIICXQIBAAKBgQCZXNNimvGTm9weiPC3my0+ZmRwWUAG0xx+CKjmJkapHdSPMbu5\n" +
                "tzdDKksiA3QVpOQX5G0Wxl52kNLd/zPuReCDOWKUlso6/SDpHOXByRZKB9Od45Co\n" +
                "MUn/FwuDUEdgSr9AGWMH0luGMDVI/+TjzYaT5XWTDMdMeOK8VWxSxgra5wIDAQAB\n" +
                "AoGBAIbnaaa2Z0SR+Ln/ecf4v37BcR6G09RtBgYzteblyohfDih79gcyjHEPlhGw\n" +
                "ef/EEUSXEgLTsiqX0HWpVNQHMarAKji+SdirjWt/ee8LxcDqMTeXGUpAOK37n+tx\n" +
                "Ejrkd8rddwgSHBJikEGIxLt9OPt6tgw4SrYsB/nHGN6ICOG5AkEAy4roVlQ6EQLO\n" +
                "mXoGH7Tg62NYhBcGxTVPz2Y3SMjV6P+j4nC24Z2TjyazGilSVDB4nJ+stQkubMoK\n" +
                "A7DZrVheswJBAMDjM4RFkcZt44ivf++cTLaYgSAKbQLcCMDmBhtIis4WvTLiQHyy\n" +
                "pgU2n0WDIpc5cYKjKlvi1vHGptJyVRwXrP0CQD0Nm4dZmFlF6EatDW0xSk4Q7Joi\n" +
                "dgttZFUnqemRJGjRVY00lgayx3Im/44XWvSZ3XPNiXZ8HIrRR5O31nNikHUCQQCa\n" +
                "SaJ9nUBbnq6wOOF3AmkCbb5rqKtF7Ec8NUKRNFeDPgEc4ImAtU3DQcvoyFo06If5\n" +
                "XRaW5T3Vq3bpQvb9P5rpAkAfWb4x8bV345cG4UwaGDKMbaCPENrXOgRaSx6G4/EU\n" +
                "x3eEZJJ5Z0FCLnCSVrdv5DDqfhjvED3o8XtJlNDqleJZ\n" +
                "-----END RSA PRIVATE KEY-----\n";
        byte[] signature = null;
        boolean success = false;
        try {
            signatureEngine = SignatureEngine.getInstance(Sha1WithRsaEncryptionSignatureEngine.objectIdentifierString);
        } catch (SignatureEngineException e) {
            e.printStackTrace();
        }
        try {
            signatureEngine.init(pemFileContent.getBytes(), SignatureEngine.KeyType.PEM_ENCODED, null);
        } catch (SignatureEngineException e) {
            e.printStackTrace();
        }
        try {
            signature = signatureEngine.sign("hihi".getBytes());
            success = true;
        } catch (SignatureEngineException e) {
            e.printStackTrace();
        }
        assertNotEquals(null, signature);
        assertArrayEquals(new byte[]{(byte) 0x66, (byte) 0xbe, (byte) 0x4c, (byte) 0xeb, (byte) 0x0b, (byte) 0x0d, (byte) 0xfb, (byte) 0xdd, (byte) 0x1e, (byte) 0xf8, (byte) 0xaa, (byte) 0xab, (byte) 0x0b, (byte) 0xfb, (byte) 0xf2, (byte) 0xba, (byte) 0x7d, (byte) 0x46, (byte) 0x4e, (byte) 0xdc, (byte) 0xbf, (byte) 0x42, (byte) 0x39, (byte) 0x0a, (byte) 0xe5, (byte) 0xc9, (byte) 0x21, (byte) 0x74, (byte) 0x38, (byte) 0x2a, (byte) 0xe1, (byte) 0x97, (byte) 0xbe, (byte) 0x7e, (byte) 0xe0, (byte) 0xc5, (byte) 0xa3, (byte) 0x22, (byte) 0x10, (byte) 0x21, (byte) 0xa9, (byte) 0xde, (byte) 0x72, (byte) 0x64, (byte) 0xa2, (byte) 0x98, (byte) 0xb8, (byte) 0xd7, (byte) 0x47, (byte) 0xcc, (byte) 0x70, (byte) 0x58, (byte) 0x86, (byte) 0xb2, (byte) 0x35, (byte) 0x47, (byte) 0xdc, (byte) 0x6b, (byte) 0x89, (byte) 0x56, (byte) 0xb5, (byte) 0xc4, (byte) 0x8f, (byte) 0xb4, (byte) 0x0b, (byte) 0x1f, (byte) 0x9a, (byte) 0x71, (byte) 0x29, (byte) 0x71, (byte) 0x89, (byte) 0xd0, (byte) 0xec, (byte) 0x4c, (byte) 0x81, (byte) 0x86, (byte) 0x54, (byte) 0xbc, (byte) 0x2e, (byte) 0x3c, (byte) 0x2e, (byte) 0x2e, (byte) 0xef, (byte) 0x84, (byte) 0x9d, (byte) 0xeb, (byte) 0xf4, (byte) 0xbc, (byte) 0xba, (byte) 0xf8, (byte) 0x81, (byte) 0x31, (byte) 0x52, (byte) 0xe3, (byte) 0x41, (byte) 0xfb, (byte) 0xed, (byte) 0xb3, (byte) 0x2d, (byte) 0xde, (byte) 0xcd, (byte) 0x1a, (byte) 0x4c, (byte) 0x57, (byte) 0xdd, (byte) 0x3b, (byte) 0x6c, (byte) 0x37, (byte) 0x9e, (byte) 0xb9, (byte) 0x8e, (byte) 0x16, (byte) 0x4a, (byte) 0x61, (byte) 0x51, (byte) 0xca, (byte) 0xe7, (byte) 0x6f, (byte) 0x44, (byte) 0xc6, (byte) 0xa5, (byte) 0x20, (byte) 0xe7, (byte) 0x53, (byte) 0x18, (byte) 0x88, (byte) 0x23, (byte) 0xb6}, signature);
    }
}