/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.constants;

import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import java.util.HashMap;
import java.util.Map;

public enum X509SignatureAlgorithm {
    MD2_WITH_RSA_ENCRYPTION(
            "md2WithRSAEncryption",
            "1.2.840.113549.1.1.2",
            SignatureAlgorithm.RSA_PKCS1,
            HashAlgorithm.MD2),
    MD4_WITH_RSA_ENCRYPTION(
            "md4WithRSAEncryption",
            "1.2.840.113549.1.1.3",
            SignatureAlgorithm.RSA_PKCS1,
            HashAlgorithm.MD4),
    MD5_WITH_RSA_ENCRYPTION(
            "md5WithRSAEncryption",
            "1.2.840.113549.1.1.4",
            SignatureAlgorithm.RSA_PKCS1,
            HashAlgorithm.MD5),
    SHA1_WITH_RSA_ENCRYPTION(
            "sha1WithRSAEncryption",
            "1.2.840.113549.1.1.5",
            SignatureAlgorithm.RSA_PKCS1,
            HashAlgorithm.SHA1),
    SHA256_WITH_RSA_ENCRYPTION(
            "sha256WithRSAEncryption",
            "1.2.840.113549.1.1.11",
            SignatureAlgorithm.RSA_PKCS1,
            HashAlgorithm.SHA256),
    SHA384_WITH_RSA_ENCRYPTION(
            "sha384WithRSAEncryption",
            "1.2.840.113549.1.1.12",
            SignatureAlgorithm.RSA_PKCS1,
            HashAlgorithm.SHA384),
    SHA512_WITH_RSA_ENCRYPTION(
            "sha512WithRSAEncryption",
            "1.2.840.113549.1.1.13",
            SignatureAlgorithm.RSA_PKCS1,
            HashAlgorithm.SHA512),
    SHA224_WITH_RSA_ENCRYPTION(
            "sha224WithRSAEncryption",
            "1.2.840.113549.1.1.14",
            SignatureAlgorithm.RSA_PKCS1,
            HashAlgorithm.SHA224),
    RSASSA_PSS(
            "RSASSA-PSS",
            "1.2.840.113549.1.1.10",
            SignatureAlgorithm.RSA_SSA_PSS,
            null), // Hash algorithm is defined by parameters
    DSA_WITH_SHA1("DSAwithSHA1", "1.2.840.10040.4.3", SignatureAlgorithm.DSA, HashAlgorithm.SHA1),
    DSA_WITH_SHA224(
            "DSAwithSHA224",
            "2.16.840.1.101.3.4.3.1",
            SignatureAlgorithm.DSA,
            HashAlgorithm.SHA224),
    DSA_WITH_SHA256(
            "DSAwithSHA256",
            "2.16.840.1.101.3.4.3.2",
            SignatureAlgorithm.DSA,
            HashAlgorithm.SHA256),
    DSA_WITH_SHA384(
            "DSAwithSHA384",
            "2.16.840.1.101.3.4.3.3",
            SignatureAlgorithm.DSA,
            HashAlgorithm.SHA384),
    DSA_WITH_SHA512(
            "DSAwithSHA512",
            "2.16.840.1.101.3.4.3.4",
            SignatureAlgorithm.DSA,
            HashAlgorithm.SHA512),
    ECDSA_WITH_SHA1(
            "ecdsa-with-SHA1", "1.2.840.10045.4.1", SignatureAlgorithm.ECDSA, HashAlgorithm.SHA1),
    ECDSA_WITH_SHA224(
            "ecdsa-with-SHA224",
            "1.2.840.10045.4.3.1",
            SignatureAlgorithm.ECDSA,
            HashAlgorithm.SHA224),
    ECDSA_WITH_SHA256(
            "ecdsa-with-SHA256",
            "1.2.840.10045.4.3.2",
            SignatureAlgorithm.ECDSA,
            HashAlgorithm.SHA256),
    ECDSA_WITH_SHA384(
            "ecdsa-with-SHA384",
            "1.2.840.10045.4.3.3",
            SignatureAlgorithm.ECDSA,
            HashAlgorithm.SHA384),
    ECDSA_WITH_SHA512(
            "ecdsa-with-SHA512",
            "1.2.840.10045.4.3.4",
            SignatureAlgorithm.ECDSA,
            HashAlgorithm.SHA512);

    private static final Map<String, X509SignatureAlgorithm> oidMap = new HashMap<>();

    static {
        for (X509SignatureAlgorithm algorithm : values()) {
            oidMap.put(algorithm.getOid().toString(), algorithm);
        }
    }

    private final String humanReadableName;
    private final ObjectIdentifier oid;
    private final SignatureAlgorithm signatureAlgorithm;
    /**
     * Some signature algorithms do not explicitly specify a hash algorithm, so this value might be
     * null.
     */
    private final HashAlgorithm hashAlgorithm;

    private X509SignatureAlgorithm(
            String humanReadableName,
            String oid,
            SignatureAlgorithm signatureAlgorithm,
            HashAlgorithm hashAlgorithm) {
        this.humanReadableName = humanReadableName;
        this.oid = new ObjectIdentifier(oid);
        this.signatureAlgorithm = signatureAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
    }

    public String getHumanReadableName() {
        return humanReadableName;
    }

    public ObjectIdentifier getOid() {
        return oid;
    }

    public static X509SignatureAlgorithm decodeFromOidBytes(byte[] oidBytes) {
        ObjectIdentifier objectIdentifier = new ObjectIdentifier(oidBytes);
        return oidMap.get(objectIdentifier.toString());
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }
}
