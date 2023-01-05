/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.filesystem;

import static org.junit.jupiter.api.Assertions.fail;

import de.rub.nds.x509attacker.x509.base.X509CertificateChain;
import de.rub.nds.x509attacker.x509.base.X509Component;
import java.io.IOException;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class CertificateIoTest {

    private static final Logger LOGGER = LogManager.getLogger();

    public CertificateIoTest() {}

    @ParameterizedTest
    @MethodSource("testCertsProvider")
    void testWithTestData(String resourcePath) throws IOException {
        LOGGER.debug("Testing: " + resourcePath);
        try {
            X509CertificateChain chain =
                    CertificateIo.readPemChain(getClass().getResourceAsStream(resourcePath));
            X509Component publicKey =
                    chain.getLeaf()
                            .getTbsCertificate()
                            .getSubjectPublicKeyInfo()
                            .getSubjectPublicKeyBitString()
                            .getPublicKey();
            Assertions.assertNotNull(
                    publicKey,
                    "Each certificate has a public key that should be readable: " + resourcePath);
        } catch (Exception E) {
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
