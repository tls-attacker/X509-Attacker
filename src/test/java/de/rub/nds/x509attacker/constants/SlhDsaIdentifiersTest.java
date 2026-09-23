/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.constants;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.constants.SlhDsaParameters;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** The pure and pre-hash SLH-DSA algorithm identifiers of RFC 9909, Section 3. */
class SlhDsaIdentifiersTest {

    @ParameterizedTest
    @CsvSource({
        "SLH_DSA_SHA2_128S, 2.16.840.1.101.3.4.3.20, SLH_DSA_SHA2_128S, NONE",
        "SLH_DSA_SHA2_128F, 2.16.840.1.101.3.4.3.21, SLH_DSA_SHA2_128F, NONE",
        "SLH_DSA_SHA2_192S, 2.16.840.1.101.3.4.3.22, SLH_DSA_SHA2_192S, NONE",
        "SLH_DSA_SHA2_192F, 2.16.840.1.101.3.4.3.23, SLH_DSA_SHA2_192F, NONE",
        "SLH_DSA_SHA2_256S, 2.16.840.1.101.3.4.3.24, SLH_DSA_SHA2_256S, NONE",
        "SLH_DSA_SHA2_256F, 2.16.840.1.101.3.4.3.25, SLH_DSA_SHA2_256F, NONE",
        "SLH_DSA_SHAKE_128S, 2.16.840.1.101.3.4.3.26, SLH_DSA_SHAKE_128S, NONE",
        "SLH_DSA_SHAKE_128F, 2.16.840.1.101.3.4.3.27, SLH_DSA_SHAKE_128F, NONE",
        "SLH_DSA_SHAKE_192S, 2.16.840.1.101.3.4.3.28, SLH_DSA_SHAKE_192S, NONE",
        "SLH_DSA_SHAKE_192F, 2.16.840.1.101.3.4.3.29, SLH_DSA_SHAKE_192F, NONE",
        "SLH_DSA_SHAKE_256S, 2.16.840.1.101.3.4.3.30, SLH_DSA_SHAKE_256S, NONE",
        "SLH_DSA_SHAKE_256F, 2.16.840.1.101.3.4.3.31, SLH_DSA_SHAKE_256F, NONE",
        "HASH_SLH_DSA_SHA2_128S_WITH_SHA256, 2.16.840.1.101.3.4.3.35, SLH_DSA_SHA2_128S, SHA256",
        "HASH_SLH_DSA_SHA2_128F_WITH_SHA256, 2.16.840.1.101.3.4.3.36, SLH_DSA_SHA2_128F, SHA256",
        "HASH_SLH_DSA_SHA2_192S_WITH_SHA512, 2.16.840.1.101.3.4.3.37, SLH_DSA_SHA2_192S, SHA512",
        "HASH_SLH_DSA_SHA2_192F_WITH_SHA512, 2.16.840.1.101.3.4.3.38, SLH_DSA_SHA2_192F, SHA512",
        "HASH_SLH_DSA_SHA2_256S_WITH_SHA512, 2.16.840.1.101.3.4.3.39, SLH_DSA_SHA2_256S, SHA512",
        "HASH_SLH_DSA_SHA2_256F_WITH_SHA512, 2.16.840.1.101.3.4.3.40, SLH_DSA_SHA2_256F, SHA512",
        "HASH_SLH_DSA_SHAKE_128S_WITH_SHAKE128, 2.16.840.1.101.3.4.3.41, SLH_DSA_SHAKE_128S,"
                + " SHAKE128",
        "HASH_SLH_DSA_SHAKE_128F_WITH_SHAKE128, 2.16.840.1.101.3.4.3.42, SLH_DSA_SHAKE_128F,"
                + " SHAKE128",
        "HASH_SLH_DSA_SHAKE_192S_WITH_SHAKE256, 2.16.840.1.101.3.4.3.43, SLH_DSA_SHAKE_192S,"
                + " SHAKE256",
        "HASH_SLH_DSA_SHAKE_192F_WITH_SHAKE256, 2.16.840.1.101.3.4.3.44, SLH_DSA_SHAKE_192F,"
                + " SHAKE256",
        "HASH_SLH_DSA_SHAKE_256S_WITH_SHAKE256, 2.16.840.1.101.3.4.3.45, SLH_DSA_SHAKE_256S,"
                + " SHAKE256",
        "HASH_SLH_DSA_SHAKE_256F_WITH_SHAKE256, 2.16.840.1.101.3.4.3.46, SLH_DSA_SHAKE_256F,"
                + " SHAKE256"
    })
    void testIdentifiers(
            String name, String oid, SlhDsaParameters parameters, HashAlgorithm preHash) {
        byte[] encodedOid = new ObjectIdentifier(oid).getEncoded();
        // NONE stands for pure SLH-DSA, which has no separate hash algorithm
        HashAlgorithm expectedHashAlgorithm = preHash == HashAlgorithm.NONE ? null : preHash;

        X509PublicKeyType publicKeyType = X509PublicKeyType.decodeFromOidBytes(encodedOid);
        assertEquals(X509PublicKeyType.valueOf(name), publicKeyType);
        assertEquals(parameters, publicKeyType.getSlhDsaParameters());
        assertTrue(publicKeyType.isSlhDsa());
        assertFalse(publicKeyType.isMlDsa());
        assertFalse(publicKeyType.isEc());
        assertTrue(publicKeyType.canBeUsedWithSignatureAlgorithm(SignatureAlgorithm.SLH_DSA));
        assertFalse(publicKeyType.canBeUsedWithSignatureAlgorithm(SignatureAlgorithm.ML_DSA));

        X509SignatureAlgorithm signatureAlgorithm =
                X509SignatureAlgorithm.decodeFromOidBytes(encodedOid);
        assertEquals(X509SignatureAlgorithm.valueOf(name), signatureAlgorithm);
        assertEquals(SignatureAlgorithm.SLH_DSA, signatureAlgorithm.getSignatureAlgorithm());
        assertEquals(expectedHashAlgorithm, signatureAlgorithm.getHashAlgorithm());
    }

    @ParameterizedTest
    @CsvSource({"RSA", "ECDH_ECDSA", "ED25519", "ML_DSA_44"})
    void testOtherKeyTypesHaveNoSlhDsaParameters(X509PublicKeyType publicKeyType) {
        assertNull(publicKeyType.getSlhDsaParameters());
        assertFalse(publicKeyType.isSlhDsa());
    }
}
