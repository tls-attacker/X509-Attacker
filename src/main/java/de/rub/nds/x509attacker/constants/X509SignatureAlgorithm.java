/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.constants;

import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.x509attacker.signatureengine.keyparsers.SignatureKeyType;
import java.util.HashMap;
import java.util.Map;

public enum X509SignatureAlgorithm {
    MD2_WITH_RSA_ENCRYPTION("md2WithRSAEncryption", "1.2.840.113549.1.1.2", SignatureKeyType.RSA),
    MD4_WITH_RSA_ENCRYPTION("md4WithRSAEncryption", "1.2.840.113549.1.1.3", SignatureKeyType.RSA),
    MD5_WITH_RSA_ENCRYPTION("md5WithRSAEncryption", "1.2.840.113549.1.1.4", SignatureKeyType.RSA),
    SHA1_WITH_RSA_ENCRYPTION("sha1WithRSAEncryption", "1.2.840.113549.1.1.5", SignatureKeyType.RSA),
    SHA256_WITH_RSA_ENCRYPTION(
            "sha256WithRSAEncryption", "1.2.840.113549.1.1.11", SignatureKeyType.RSA),
    SHA384_WITH_RSA_ENCRYPTION(
            "sha384WithRSAEncryption", "1.2.840.113549.1.1.12", SignatureKeyType.RSA),
    SHA512_WITH_RSA_ENCRYPTION(
            "sha512WithRSAEncryption", "1.2.840.113549.1.1.13", SignatureKeyType.RSA),
    SHA224_WITH_RSA_ENCRYPTION(
            "sha224WithRSAEncryption", "1.2.840.113549.1.1.14", SignatureKeyType.RSA),
    DSA_WITH_SHA1("DSAwithSHA1", "1.2.840.10040.4.3", SignatureKeyType.DSA),
    DSA_WITH_SHA224("DSAwithSHA224", "2.16.840.1.101.3.4.3.1", SignatureKeyType.DSA),
    DSA_WITH_SHA256("DSAwithSHA256", "2.16.840.1.101.3.4.3.2", SignatureKeyType.DSA),
    DSA_WITH_SHA384("DSAwithSHA384", "2.16.840.1.101.3.4.3.3", SignatureKeyType.DSA),
    DSA_WITH_SHA512("DSAwithSHA512", "2.16.840.1.101.3.4.3.4", SignatureKeyType.DSA),
    ECDSA_WITH_SHA1("ecdsa-with-SHA1", "1.2.840.10045.4.1", SignatureKeyType.ECDSA),
    ECDSA_WITH_SHA224("ecdsa-with-SHA224", "1.2.840.10045.4.3.1", SignatureKeyType.ECDSA),
    ECDSA_WITH_SHA256("ecdsa-with-SHA256", "1.2.840.10045.4.3.2", SignatureKeyType.ECDSA),
    ECDSA_WITH_SHA384("ecdsa-with-SHA384", "1.2.840.10045.4.3.3", SignatureKeyType.ECDSA),
    ECDSA_WITH_SHA512("ecdsa-with-SHA512", "1.2.840.10045.4.3.4", SignatureKeyType.ECDSA);

    private static final Map<String, X509SignatureAlgorithm> oidMap = new HashMap<>();

    static {
        for (X509SignatureAlgorithm algorithm : values()) {
            oidMap.put(algorithm.getOid().toString(), algorithm);
        }
    }

    private final String humanReadableName;
    private final ObjectIdentifier oid;
    private final SignatureKeyType keyType;

    private X509SignatureAlgorithm(String humanReadableName, String oid, SignatureKeyType keyType) {
        this.humanReadableName = humanReadableName;
        this.oid = new ObjectIdentifier(oid);
        this.keyType = keyType;
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

    public SignatureKeyType getKeyType() {
        return keyType;
    }
}
