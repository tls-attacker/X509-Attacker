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

import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.constants.SlhDsaParameters;
import de.rub.nds.protocol.crypto.key.SlhDsaPublicKey;
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
 * SLH-DSA certificates carry the FIPS 205 public key directly in the subjectPublicKey BIT STRING
 * and have no AlgorithmIdentifier parameters (RFC 9909). The test certificates cover all twelve
 * pure SLH-DSA parameter sets and one HashSLH-DSA certificate per pre-hash function.
 */
public class X509SlhDsaPublicKeyTest {

    static Stream<Arguments> slhDsaCertificatesProvider() {
        return Stream.of(
                pure("slhdsa_sha2_128s", X509PublicKeyType.SLH_DSA_SHA2_128S),
                pure("slhdsa_sha2_128f", X509PublicKeyType.SLH_DSA_SHA2_128F),
                pure("slhdsa_sha2_192s", X509PublicKeyType.SLH_DSA_SHA2_192S),
                pure("slhdsa_sha2_192f", X509PublicKeyType.SLH_DSA_SHA2_192F),
                pure("slhdsa_sha2_256s", X509PublicKeyType.SLH_DSA_SHA2_256S),
                pure("slhdsa_sha2_256f", X509PublicKeyType.SLH_DSA_SHA2_256F),
                pure("slhdsa_shake_128s", X509PublicKeyType.SLH_DSA_SHAKE_128S),
                pure("slhdsa_shake_128f", X509PublicKeyType.SLH_DSA_SHAKE_128F),
                pure("slhdsa_shake_192s", X509PublicKeyType.SLH_DSA_SHAKE_192S),
                pure("slhdsa_shake_192f", X509PublicKeyType.SLH_DSA_SHAKE_192F),
                pure("slhdsa_shake_256s", X509PublicKeyType.SLH_DSA_SHAKE_256S),
                pure("slhdsa_shake_256f", X509PublicKeyType.SLH_DSA_SHAKE_256F),
                preHash(
                        "hashslhdsa_sha2_128s_sha256",
                        X509PublicKeyType.HASH_SLH_DSA_SHA2_128S_WITH_SHA256,
                        SlhDsaParameters.SLH_DSA_SHA2_128S,
                        HashAlgorithm.SHA256),
                preHash(
                        "hashslhdsa_sha2_192s_sha512",
                        X509PublicKeyType.HASH_SLH_DSA_SHA2_192S_WITH_SHA512,
                        SlhDsaParameters.SLH_DSA_SHA2_192S,
                        HashAlgorithm.SHA512),
                preHash(
                        "hashslhdsa_shake_128s_shake128",
                        X509PublicKeyType.HASH_SLH_DSA_SHAKE_128S_WITH_SHAKE128,
                        SlhDsaParameters.SLH_DSA_SHAKE_128S,
                        HashAlgorithm.SHAKE128),
                preHash(
                        "hashslhdsa_shake_192s_shake256",
                        X509PublicKeyType.HASH_SLH_DSA_SHAKE_192S_WITH_SHAKE256,
                        SlhDsaParameters.SLH_DSA_SHAKE_192S,
                        HashAlgorithm.SHAKE256));
    }

    private static Arguments pure(String name, X509PublicKeyType keyType) {
        return Arguments.of(
                "/testcerts/" + name + "_cert.pem",
                keyType,
                SlhDsaParameters.valueOf(keyType.name()),
                X509SignatureAlgorithm.valueOf(keyType.name()),
                null);
    }

    private static Arguments preHash(
            String name,
            X509PublicKeyType keyType,
            SlhDsaParameters parameters,
            HashAlgorithm hashAlgorithm) {
        return Arguments.of(
                "/testcerts/" + name + "_cert.pem",
                keyType,
                parameters,
                X509SignatureAlgorithm.valueOf(keyType.name()),
                hashAlgorithm);
    }

    @ParameterizedTest
    @MethodSource("slhDsaCertificatesProvider")
    void testPublicKeyIsParsed(
            String resourcePath,
            X509PublicKeyType expectedKeyType,
            SlhDsaParameters expectedParameters,
            X509SignatureAlgorithm expectedSignatureAlgorithm,
            HashAlgorithm expectedHashAlgorithm)
            throws IOException {
        X509Certificate certificate = readCertificate(resourcePath);

        assertEquals(expectedKeyType, certificate.getCertificateKeyType());
        X509SlhDsaPublicKey publicKey =
                assertInstanceOf(X509SlhDsaPublicKey.class, certificate.getPublicKey());
        assertEquals(expectedParameters, publicKey.getSlhDsaParameters());
        assertEquals(
                expectedParameters.getPublicKeySizeBytes(),
                publicKey.getPublicKeyBytes().getValue().length);
    }

    @ParameterizedTest
    @MethodSource("slhDsaCertificatesProvider")
    void testPublicKeyContainerIsCreated(
            String resourcePath,
            X509PublicKeyType expectedKeyType,
            SlhDsaParameters expectedParameters,
            X509SignatureAlgorithm expectedSignatureAlgorithm,
            HashAlgorithm expectedHashAlgorithm)
            throws IOException {
        X509Certificate certificate = readCertificate(resourcePath);

        SlhDsaPublicKey container =
                assertInstanceOf(SlhDsaPublicKey.class, certificate.getPublicKeyContainer());
        assertEquals(expectedParameters, container.getParameters());
        assertEquals(expectedParameters.getPublicKeySizeBytes() * 8, container.length());
        assertEquals(expectedParameters.getN(), container.getPkSeed().length);
        assertEquals(expectedParameters.getN(), container.getPkRoot().length);
    }

    @ParameterizedTest
    @MethodSource("slhDsaCertificatesProvider")
    void testSignatureAlgorithmIsParsed(
            String resourcePath,
            X509PublicKeyType expectedKeyType,
            SlhDsaParameters expectedParameters,
            X509SignatureAlgorithm expectedSignatureAlgorithm,
            HashAlgorithm expectedHashAlgorithm)
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
        assertEquals(
                SignatureAlgorithm.SLH_DSA, expectedSignatureAlgorithm.getSignatureAlgorithm());
        // Pure SLH-DSA hashes the message internally, HashSLH-DSA signs a pre-computed digest
        assertEquals(expectedHashAlgorithm, certificate.getHashAlgorithm());
        assertEquals(
                expectedParameters.getSignatureSizeBytes(),
                certificate.getSignature().getUsedBits().getValue().length);
    }

    @ParameterizedTest
    @MethodSource("slhDsaCertificatesProvider")
    void testAlgorithmIdentifierParametersAreAbsent(
            String resourcePath,
            X509PublicKeyType expectedKeyType,
            SlhDsaParameters expectedParameters,
            X509SignatureAlgorithm expectedSignatureAlgorithm,
            HashAlgorithm expectedHashAlgorithm)
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
    @MethodSource("slhDsaCertificatesProvider")
    void testReserializationIsByteIdentical(
            String resourcePath,
            X509PublicKeyType expectedKeyType,
            SlhDsaParameters expectedParameters,
            X509SignatureAlgorithm expectedSignatureAlgorithm,
            HashAlgorithm expectedHashAlgorithm)
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
