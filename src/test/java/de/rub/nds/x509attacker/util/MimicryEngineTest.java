/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.key.DsaPublicKey;
import de.rub.nds.protocol.crypto.key.EcdsaPublicKey;
import de.rub.nds.protocol.crypto.key.RsaPublicKey;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.filesystem.CertificateIo;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class MimicryEngineTest {

    private static final Logger LOGGER = LogManager.getLogger();

    public MimicryEngineTest() {}

    @ParameterizedTest
    @MethodSource("testCertsProvider")
    public void testCreateMimicryCertificate(String resourcePath) {
        LOGGER.debug("Testing: " + resourcePath);
        byte[] original = null;
        byte[] forged = null;
        try {
            X509Chooser chooser = new X509Chooser(new X509CertificateConfig(), new X509Context());
            X509CertificateChain originalChain =
                    CertificateIo.readPemChain(getClass().getResourceAsStream(resourcePath));
            X509CertificateConfig finalConfig =
                    new X509CertificateConfig(); // This will store the private keys
            X509CertificateChain forgedChain =
                    MimicryEngine.createMimicryCertificateChain(
                            List.of(finalConfig), originalChain);
            for (int i = 0; i < originalChain.size(); i++) {
                original = originalChain.getCertificate(i).getSerializer(chooser).serialize();
                forged = forgedChain.getCertificate(i).getSerializer(chooser).serialize();
                X509Certificate rereadCertificiate = new X509Certificate("cert");
                rereadCertificiate
                        .getParser(chooser)
                        .parse(new BufferedInputStream(new ByteArrayInputStream(forged)));
                X509Certificate originalCertificate = originalChain.getCertificate(i);
                assertEquals(
                        originalCertificate.getPublicKey().getX509PublicKeyType(),
                        rereadCertificiate.getPublicKey().getX509PublicKeyType());
                assertFalse(Arrays.equals(original, forged));
                if (rereadCertificiate.getCertificateKeyType() == X509PublicKeyType.RSA) {
                    RsaPublicKey publicKey =
                            (RsaPublicKey) rereadCertificiate.getPublicKeyContainer();
                    assertEquals(finalConfig.getDefaultSubjectRsaModulus(), publicKey.getModulus());
                    assertEquals(
                            finalConfig.getDefaultSubjectRsaPublicExponent(),
                            publicKey.getPublicExponent());
                } else if (rereadCertificiate.getCertificateKeyType()
                        == X509PublicKeyType.ECDH_ECDSA) {
                    // Expected point:
                    Point expectedPublicKey =
                            originalCertificate
                                    .getEllipticCurve()
                                    .getGroup()
                                    .nTimesGroupOperationOnGenerator(
                                            finalConfig.getDefaultSubjectEcPrivateKey());

                    EcdsaPublicKey publicKey =
                            (EcdsaPublicKey) rereadCertificiate.getPublicKeyContainer();
                    assertEquals(
                            ((EcdsaPublicKey) originalCertificate.getPublicKeyContainer())
                                    .getParameters(),
                            publicKey.getParameters());
                    assertEquals(expectedPublicKey, publicKey.getPublicPoint());

                } else if (rereadCertificiate.getCertificateKeyType() == X509PublicKeyType.DSA) {
                    DsaPublicKey publicKey =
                            (DsaPublicKey) rereadCertificiate.getPublicKeyContainer();
                    DsaPublicKey originialPublicKey =
                            (DsaPublicKey) originalCertificate.getPublicKeyContainer();
                    assertEquals(originialPublicKey.getGenerator(), publicKey.getGenerator());
                    assertEquals(originialPublicKey.getModulus(), publicKey.getModulus());
                    assertEquals(originialPublicKey.getQ(), publicKey.getQ());
                    // Compute expected public key
                    BigInteger expectedPublicKey =
                            originialPublicKey
                                    .getGenerator()
                                    .modPow(
                                            finalConfig.getDefaultSubjectDsaPrivateKey(),
                                            originialPublicKey.getModulus());
                    assertEquals(expectedPublicKey, publicKey.getY());
                } else {
                    fail("Unknown Key Type: " + rereadCertificiate.getCertificateKeyType());
                }
                assertTrue(
                        isRoughlySameLength(
                                originalCertificate.getSignature().getContent().getValue().length,
                                rereadCertificiate.getSignature().getContent().getValue().length));
            }
        } catch (Exception E) {
            LOGGER.debug("Problem", E);
            fail(resourcePath, E);
        }
    }

    /**
     * Fuzzy comparison because the encoded length can changed depending on leading bits...
     *
     * @param a
     * @param b
     * @return
     */
    public boolean isRoughlySameLength(int a, int b) {
        if (a < b - 64 || a > b + 64) {
            return false;
        } else {
            return true;
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
