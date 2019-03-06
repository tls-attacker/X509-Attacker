package de.rub.nds.x509attacker.signatureengine;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

import java.security.Security;

import static org.junit.Assert.*;

public class DsaWithSha1SignatureEngineTest {

    @Test
    public void testInvocation() {
        Security.addProvider(new BouncyCastleProvider());
        SignatureEngine signatureEngine = null;
        try {
            signatureEngine = SignatureEngine.getInstance(DsaWithSha1SignatureEngine.objectIdentifierString);
        } catch (SignatureEngineException e) {
            e.printStackTrace();
        }
        assertNotEquals(null, signatureEngine);
    }

    @Test
    public void testParsePemKey() {
        Security.addProvider(new BouncyCastleProvider());
        SignatureEngine signatureEngine = null;
        String pemFileContent = "-----BEGIN DSA PRIVATE KEY-----\n" +
                "MIIDTQIBAAKCAQEAj3k12bmq6b+r7Yh6z0lRtvMuxZ47rzcY6OrElh8+/TYG50NR\n" +
                "qcQYMzm4CefCrhxTm6dHW4XQEa24tHmHdUmEaVysDo8UszYIKKIv+icRCj1iqZNF\n" +
                "NAmg/mlsRlj4S90ggZw3CaAQV7GVrc0AIz26VIS2KR+dZI74g0SGd5ec7AS0NKas\n" +
                "LnXpmF3iPbApL8ERjJ/6nYGB5zONt5K3MNe540lZL2gJmHIVORXqPWuLRlPGM0WP\n" +
                "gDsypMLg8nKQJW5OP4o7CDihxFDk4YwaKaN9316hQ95LZv8EkD7VzxYj4VjUh8YI\n" +
                "6X8hHNgdyiPLbjgHZfgi40K+SEwFdjk5YBzWZwIdALr2lqaFePff3uf6Z8l3x4Xv\n" +
                "MrIzuuWAwLzVaV0CggEAFqZcWCBIUHBOdQKjl1cEDTTaOjR4wVTU5KXALSQu4E+W\n" +
                "5h5L0JBKvayPN+6x4J8xgtI8kEPLZC+IAEFg7fnKCbMgdqecMqYn8kc+kYebosTn\n" +
                "RL0ggVRMtVuALDaNH6g+1InpTg+gaI4yQopceMR4xo0FJ7ccmjq7CwvhLERoljnn\n" +
                "08502xAaZaorh/ZMaCbbPscvS1WZg0u07bAvfJDppJbTpV1TW+v8RdT2GfY/Pe27\n" +
                "hzklwvIk4HcxKW2oh+weR0j4fvtf3rdUhDFrIjLe5VPdrwIRKw0fAtowlzIk/ieu\n" +
                "2oudSyki2bqL457Z4QOmPFKBC8aIt+LtQxbh7xfb3gKCAQAoqQnmDCQK0eKaB+0D\n" +
                "9EpA33aEsBLkCjkM7EFXq0XgCppl6Gww1J5SiT1FZBGS73Bz92OqQTl1MTNOv3TK\n" +
                "i5cOlbJ/eY3u5OF7KAYZLKF2YamSPe7Q4DZZ/kz0VzD9jVThp2yTP0DTz/HMJPtV\n" +
                "RtMAufUWR1AV0EgR8b/Pmp5Lltf//tg7JzTX1PxzO2iN6pRNUp0K+faXwf4RMsax\n" +
                "SHm5trTNQqsVTtlFLPUMmp1l4fgrcFmRUAdwmwV7KhVffPM5gVDBxcJ3lwpHWIBh\n" +
                "oJcJoaCslSoXQRWFtuoU0yBsS8gvvQz5bCQ4ZS8RXukBEeL5Ary38Zk/zSRW6EtC\n" +
                "RV98AhxuD4dZpC6fStO+QsoE4K/nGRvn9/tFBuhl4hFD\n" +
                "-----END DSA PRIVATE KEY-----";
        boolean success = false;
        try {
            signatureEngine = SignatureEngine.getInstance(DsaWithSha1SignatureEngine.objectIdentifierString);
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
        String pemFileContent = "-----BEGIN DSA PRIVATE KEY-----\n" +
                "MIIBvAIBAAKBgQDK86tUGCP03INjylEuyPk64XPlq5yNE42VZ7WCjFrw73akIZXt\n" +
                "jTnDkzMXVFF1oznvpyM1cqlZvNjqlqSjoG+wOg3YYJoVikmRYtKMAv/5D2ea34qi\n" +
                "cGJ7bEP9wFK1IvYL9e5RCGVpNwmnfhBNXByOMWYnYuoxUEsUyAME+zGBvQIVAJfz\n" +
                "ARc0mkfu2uRqEQBvydfP9hODAoGBAJXx5SlF38Y/NStIsQy3+NgCJpFynlZG/878\n" +
                "LM0i+qo+raaOYq8eE3U4wEPXGAXbMETuiekeJzuv1n46Mmj1jnC9DE4++m8Tps85\n" +
                "ySgL3rhURGlTObh0n1oVZs6iS7s2+VnRLzmLztF24zTvUgZIgdeSRxt0kO1UZ8Oa\n" +
                "DgtCSJXxAoGBAIPy+Ib91GxTbUhNK3LLtgIMBcjYUamx+W6c+vHbunAvybc/zLks\n" +
                "unoF0v2oKFSNf3MQsWnef4wVjIvESFvOhz6hyTkLVSCdpLuNW7hLCk/bshJCzYyK\n" +
                "32PCaq72/2IEcHy7dWavWSy0rr2k6XxEevBsf5dFB9fGubMSAWlbYF+HAhRWl1P2\n" +
                "3jG48XMKYwajlPBavh8Ykg==\n" +
                "-----END DSA PRIVATE KEY-----\n";
        byte[] signature = null;
        boolean success = false;
        try {
            signatureEngine = SignatureEngine.getInstance(DsaWithSha1SignatureEngine.objectIdentifierString);
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
        // Todo: Match against known valid signature
        assertArrayEquals(new byte[]{(byte) 0x30, (byte) 0x2c, (byte) 0x02, (byte) 0x14, (byte) 0x1d, (byte) 0xd4, (byte) 0x57, (byte) 0xeb, (byte) 0x60, (byte) 0xc6, (byte) 0xc8, (byte) 0x9e, (byte) 0x3f, (byte) 0x83, (byte) 0xd3, (byte) 0xe2, (byte) 0x01, (byte) 0xda, (byte) 0xed, (byte) 0x2a, (byte) 0x14, (byte) 0xbe, (byte) 0x04, (byte) 0xc3, (byte) 0x02, (byte) 0x14, (byte) 0x19, (byte) 0x5d, (byte) 0x67, (byte) 0x44, (byte) 0x85, (byte) 0x2a, (byte) 0x1d, (byte) 0xaf, (byte) 0x3d, (byte) 0xa3, (byte) 0xcf, (byte) 0xb3, (byte) 0xee, (byte) 0x06, (byte) 0xbe, (byte) 0xbe, (byte) 0xbc, (byte) 0xf4, (byte) 0x89, (byte) 0x36}, signature);
    }
}