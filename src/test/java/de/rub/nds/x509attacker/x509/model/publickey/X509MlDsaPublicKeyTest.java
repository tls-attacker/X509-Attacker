/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model.publickey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;

import de.rub.nds.protocol.constants.MlDsaParameters;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.crypto.key.MlDsaPublicKey;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.filesystem.CertificateIo;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * ML-DSA certificates carry the FIPS 204 verification key directly in the subjectPublicKey BIT
 * STRING and have no AlgorithmIdentifier parameters (RFC 9881).
 */
public class X509MlDsaPublicKeyTest {

    static Stream<Arguments> mlDsaCertificatesProvider() {
        return Stream.of(
                Arguments.of(
                        "/testcerts/mldsa44_cert.pem",
                        X509PublicKeyType.ML_DSA_44,
                        MlDsaParameters.ML_DSA_44,
                        X509SignatureAlgorithm.ML_DSA_44),
                Arguments.of(
                        "/testcerts/mldsa65_cert.pem",
                        X509PublicKeyType.ML_DSA_65,
                        MlDsaParameters.ML_DSA_65,
                        X509SignatureAlgorithm.ML_DSA_65),
                Arguments.of(
                        "/testcerts/mldsa87_cert.pem",
                        X509PublicKeyType.ML_DSA_87,
                        MlDsaParameters.ML_DSA_87,
                        X509SignatureAlgorithm.ML_DSA_87));
    }

    @ParameterizedTest
    @MethodSource("mlDsaCertificatesProvider")
    void testPublicKeyIsParsed(
            String resourcePath,
            X509PublicKeyType expectedKeyType,
            MlDsaParameters expectedParameters,
            X509SignatureAlgorithm expectedSignatureAlgorithm)
            throws IOException {
        X509Certificate certificate = readCertificate(resourcePath);

        assertEquals(expectedKeyType, certificate.getCertificateKeyType());
        X509MlDsaPublicKey publicKey =
                assertInstanceOf(X509MlDsaPublicKey.class, certificate.getPublicKey());
        assertEquals(expectedParameters, publicKey.getMlDsaParameters());
        assertEquals(
                expectedParameters.getPublicKeySizeBytes(),
                publicKey.getVerificationKeyBytes().getValue().length);
    }

    @ParameterizedTest
    @MethodSource("mlDsaCertificatesProvider")
    void testPublicKeyContainerIsCreated(
            String resourcePath,
            X509PublicKeyType expectedKeyType,
            MlDsaParameters expectedParameters,
            X509SignatureAlgorithm expectedSignatureAlgorithm)
            throws IOException {
        X509Certificate certificate = readCertificate(resourcePath);

        MlDsaPublicKey container =
                assertInstanceOf(MlDsaPublicKey.class, certificate.getPublicKeyContainer());
        assertEquals(expectedParameters, container.getParameters());
        assertEquals(expectedParameters.getPublicKeySizeBytes() * 8, container.length());
        assertEquals(MlDsaPublicKey.RHO_SIZE_BYTES, container.getRho().length);
        assertEquals(
                expectedParameters.getPublicKeySizeBytes() - MlDsaPublicKey.RHO_SIZE_BYTES,
                container.getPackedT1().length);
    }

    @ParameterizedTest
    @MethodSource("mlDsaCertificatesProvider")
    void testSignatureAlgorithmIsParsed(
            String resourcePath,
            X509PublicKeyType expectedKeyType,
            MlDsaParameters expectedParameters,
            X509SignatureAlgorithm expectedSignatureAlgorithm)
            throws IOException {
        X509Certificate certificate = readCertificate(resourcePath);

        assertEquals(
                expectedSignatureAlgorithm,
                X509SignatureAlgorithm.decodeFromOidBytes(
                        certificate
                                .getSignatureAlgorithmIdentifier()
                                .getAlgorithm()
                                .getValueAsOid()
                                .getEncoded()));
        assertEquals(SignatureAlgorithm.ML_DSA, expectedSignatureAlgorithm.getSignatureAlgorithm());
        // Pure ML-DSA hashes the message internally, there is no separate hash algorithm
        assertNull(certificate.getHashAlgorithm());
    }

    @ParameterizedTest
    @MethodSource("mlDsaCertificatesProvider")
    void testAlgorithmIdentifierParametersAreAbsent(
            String resourcePath,
            X509PublicKeyType expectedKeyType,
            MlDsaParameters expectedParameters,
            X509SignatureAlgorithm expectedSignatureAlgorithm)
            throws IOException {
        X509Certificate certificate = readCertificate(resourcePath);

        assertNull(
                certificate
                        .getTbsCertificate()
                        .getSubjectPublicKeyInfo()
                        .getAlgorithm()
                        .getParameters());
        assertNull(certificate.getSignatureAlgorithmIdentifier().getParameters());
    }

    @ParameterizedTest
    @MethodSource("mlDsaCertificatesProvider")
    void testReserializationIsByteIdentical(
            String resourcePath,
            X509PublicKeyType expectedKeyType,
            MlDsaParameters expectedParameters,
            X509SignatureAlgorithm expectedSignatureAlgorithm)
            throws IOException {
        byte[] expectedEncoding = readDer(resourcePath);
        X509Certificate certificate = readCertificate(resourcePath);

        byte[] reserialized =
                certificate
                        .getSerializer(
                                new X509Chooser(new X509CertificateConfig(), new X509Context()))
                        .serialize();
        assertArrayEquals(expectedEncoding, reserialized);
    }

    private X509Certificate readCertificate(String resourcePath) throws IOException {
        try (InputStream inputStream = getClass().getResourceAsStream(resourcePath)) {
            X509CertificateChain chain = CertificateIo.readPemChain(inputStream);
            return chain.getLeaf();
        }
    }

    private byte[] readDer(String resourcePath) throws IOException {
        try (InputStream inputStream = getClass().getResourceAsStream(resourcePath)) {
            String pem = new String(inputStream.readAllBytes(), StandardCharsets.US_ASCII);
            String base64 = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
            return new ByteArrayInputStream(Base64.getDecoder().decode(base64)).readAllBytes();
        }
    }
}
