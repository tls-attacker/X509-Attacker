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
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import java.util.HashMap;
import java.util.Map;

public enum X509PublicKeyType {
    RSA("RSA", "1.2.840.113549.1.1.1"), // RFC3279
    DSA("DSA", "1.2.840.10040.4.1"), // RFC3279
    DH("Diffie-Hellman", "1.2.840.113549.1.3.1"), // RFC3279
    KEA("Key Exchange Algorithm", "2.16.840.1.101.2.1.1.22"), // RFC3279
    ECDH_ECDSA("Elliptic Curve", "1.2.840.10045.2.1"), // RFC3279, used for ECDH and ECDSA
    RSASSA_PSS("RSA-PSS", "1.2.840.113549.1.1.10"), // RFC4055
    RSAES_OAEP("RSA-OAEP", "1.2.840.113549.1.1.7"), // RFC4055
    GOST_R3411_94("GOST_R3411_94", "1.2.643.2.2.20"), // RFC4491
    GOST_R3411_2001("GOST_R3411_2001", "1.2.643.2.2.19"), // RFC4491
    GOST_R3411_2012("GOST_R3411_2001", "1.2.643.2.2.19"), // RFC4491
    ECDH_ONLY("ECDH", "1.3.132.1.12"), // RFC5480
    ECMQV("ECMQV", "1.3.132.1.13"), // RFC5480
    X25519("X25519", "1.3.101.110"), // RFC8410
    X448("X448", "1.3.101.111"), // RFC8410
    ED25519("Ed25519", "1.3.101.112"), // RFC8410
    ED448("Ed448", "1.3.101.113"); // RFC8410

    private static final Map<String, X509PublicKeyType> oidMap = new HashMap<>();

    static {
        for (X509PublicKeyType algorithm : values()) {
            oidMap.put(algorithm.getOid().toString(), algorithm);
        }
    }

    private final String humanReadableName;
    private final ObjectIdentifier oid;

    X509PublicKeyType(String humanReadableName, String oid) {
        this.humanReadableName = humanReadableName;
        this.oid = new ObjectIdentifier(oid);
    }

    public String getHumanReadableName() {
        return humanReadableName;
    }

    public ObjectIdentifier getOid() {
        return oid;
    }

    public static X509PublicKeyType decodeFromOidBytes(byte[] oidBytes) {
        ObjectIdentifier objectIdentifier = new ObjectIdentifier(oidBytes);
        return oidMap.get(objectIdentifier.toString());
    }

    public boolean canBeUsedWithSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        switch (this) {
            case DH:
                return false;
            case DSA:
                return signatureAlgorithm == SignatureAlgorithm.DSA;
            case ECDH_ECDSA:
                return signatureAlgorithm == SignatureAlgorithm.ECDSA;
            case ECDH_ONLY:
                return false;
            case ECMQV:
                throw new UnsupportedOperationException("Not implemented: " + this);
            case ED25519:
                return signatureAlgorithm == SignatureAlgorithm.ED25519;
            case ED448:
                return signatureAlgorithm == SignatureAlgorithm.ED448;
            case GOST_R3411_2001:
            case GOST_R3411_94:
                // TODO not sure this is correct
                return signatureAlgorithm == SignatureAlgorithm.GOSTR34102001;
            case GOST_R3411_2012:
                // TODO not sure this is correct
                return signatureAlgorithm == SignatureAlgorithm.GOSTR34102012_256
                        || signatureAlgorithm == SignatureAlgorithm.GOSTR34102012_512;
            case KEA:
                throw new UnsupportedOperationException("Not implemented: " + this);
            case RSA:
                return signatureAlgorithm == SignatureAlgorithm.RSA_PKCS1;
            case RSASSA_PSS:
                return signatureAlgorithm == SignatureAlgorithm.RSA_SSA_PSS;
            case X25519:
                return false;
            case X448:
                return false;
            case RSAES_OAEP:
                throw new UnsupportedOperationException("Not implemented: " + this);
            default:
                throw new UnsupportedOperationException("Not implemented: " + this);
        }
    }

    public boolean isEc() {
        switch (this) {
            case ECDH_ECDSA:
            case ECDH_ONLY:
            case ECMQV:
            case ED25519:
            case ED448:
            case GOST_R3411_2001:
            case GOST_R3411_2012:
            case GOST_R3411_94:
            case X25519:
            case X448:
                return true;
            case DH:
            case DSA:
            case KEA:
            case RSA:
            case RSAES_OAEP:
            case RSASSA_PSS:
                return false;
            default:
                throw new UnsupportedOperationException("Not yet implemented: " + this.name());
        }
    }
}
