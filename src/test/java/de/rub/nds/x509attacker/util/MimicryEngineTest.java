package de.rub.nds.x509attacker.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.filesystem.CertificateIo;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import de.rub.nds.x509attacker.x509.model.X509Certificate;

public class MimicryEngineTest {

    private static final Logger LOGGER = LogManager.getLogger();

    public MimicryEngineTest() {
    }

    @ParameterizedTest
    @MethodSource("testCertsProvider")
    public void testCreateMimicryCertificate(String resourcePath) {
        LOGGER.debug("Testing: " + resourcePath);
        byte[] original = null;
        byte[] forged = null;
        try {
            X509Chooser chooser = new X509Chooser(new X509CertificateConfig(), new X509Context());
            X509CertificateChain originalChain = CertificateIo
                    .readPemChain(getClass().getResourceAsStream(resourcePath));
            X509CertificateChain forgedChain = MimicryEngine
                    .createMimicryCertificate(List.of(new X509CertificateConfig()), originalChain);
            for (int i = 0; i < originalChain.size(); i++) {
                original = originalChain.getCertificate(i).getSerializer(chooser).serialize();
                forged = forgedChain.getCertificate(i).getSerializer(chooser).serialize();
                X509Certificate rereadCertificiate = new X509Certificate("cert");
                rereadCertificiate.getParser(chooser)
                        .parse(new BufferedInputStream(new ByteArrayInputStream(forged)));
                X509Certificate originalCertificate = originalChain.getCertificate(i);
                assertEquals(originalCertificate.getPublicKey().getX509PublicKeyType(),
                        rereadCertificiate.getPublicKey().getX509PublicKeyType());
                //assertTrue(original.length == forged.length);
                assertFalse(Arrays.equals(original, forged));

            }
        } catch (Exception E) {
            System.out.println("Original: " + ArrayConverter.bytesToHexString(original));
            System.out.println("Forged: " + ArrayConverter.bytesToHexString(forged));

            //E.printStackTrace();
            LOGGER.debug("Problem", E);
            fail(resourcePath, E);
        }
    }

    static Stream<Arguments> testCertsProvider() {
        return Stream.of(
                Arguments.of("/testcerts/rsa512_cert.pem"),
                Arguments.of("/testcerts/rsa1024_cert.pem"),
                Arguments.of("/testcerts/rsa2048_cert.pem"),
                Arguments.of("/testcerts/rsa4096_cert.pem"),
                Arguments.of("/testcerts/dsa1024_cert.pem"),
                Arguments.of("/testcerts/dsa2048_cert.pem"),
                Arguments.of("/testcerts/dsa3072_cert.pem"),
                Arguments.of("/testcerts/dsa_ca.pem"),
                Arguments.of("/testcerts/rsa_ca.pem"),
                Arguments.of("/testcerts/ec_rsa_cert_secp160k1.pem"),
                Arguments.of("/testcerts/ec_rsa_cert_secp160r1.pem"),
                Arguments.of("/testcerts/ec_rsa_cert_secp160r2.pem"),
                Arguments.of("/testcerts/ec_rsa_cert_secp192k1.pem"),
                Arguments.of("/testcerts/ec_rsa_cert_secp224k1.pem"),
                Arguments.of("/testcerts/ec_rsa_cert_secp224r1.pem"),
                Arguments.of("/testcerts/ec_rsa_cert_secp256k1.pem"),
                Arguments.of("/testcerts/ec_rsa_cert_secp384r1.pem"),
                Arguments.of("/testcerts/ec_rsa_cert_secp521r1.pem"),
                Arguments.of("/testcerts/ec_rsa_cert_sect163k1.pem"),
                Arguments.of("/testcerts/ec_rsa_cert_sect163r1.pem"),
                Arguments.of("/testcerts/ec_rsa_cert_sect163r2.pem"),
                Arguments.of("/testcerts/ec_rsa_cert_sect193r1.pem"),
                Arguments.of("/testcerts/ec_rsa_cert_sect193r2.pem"),
                Arguments.of("/testcerts/ec_rsa_cert_sect233k1.pem"),
                Arguments.of("/testcerts/ec_rsa_cert_sect233r1.pem"),
                Arguments.of("/testcerts/ec_rsa_cert_sect239k1.pem"),
                Arguments.of("/testcerts/ec_rsa_cert_sect283k1.pem"),
                Arguments.of("/testcerts/ec_rsa_cert_sect283r1.pem"),
                Arguments.of("/testcerts/ec_rsa_cert_sect409k1.pem"),
                Arguments.of("/testcerts/ec_rsa_cert_sect409r1.pem"),
                Arguments.of("/testcerts/ec_rsa_cert_sect571k1.pem"),
                Arguments.of("/testcerts/ec_rsa_cert_sect571r1.pem"),
                Arguments.of("/testcerts/ec_secp160k1_cert.pem"),
                Arguments.of("/testcerts/ec_secp160r1_cert.pem"),
                Arguments.of("/testcerts/ec_secp160r2_cert.pem"),
                Arguments.of("/testcerts/ec_secp192k1_cert.pem"),
                Arguments.of("/testcerts/ec_secp224k1_cert.pem"),
                Arguments.of("/testcerts/ec_secp224r1_cert.pem"),
                Arguments.of("/testcerts/ec_secp256k1_cert.pem"),
                Arguments.of("/testcerts/ec_secp384r1_cert.pem"),
                Arguments.of("/testcerts/ec_secp521r1_cert.pem"));
    }
}
