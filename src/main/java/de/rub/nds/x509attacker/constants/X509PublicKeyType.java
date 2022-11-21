/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.constants;

import de.rub.nds.x509attacker.oid.ObjectIdentifier;
import de.rub.nds.x509attacker.signatureengine.keyparsers.SignatureKeyType;
import java.util.HashMap;
import java.util.Map;

public enum X509PublicKeyType {
    RSA("RSA", "1.2.840.113549.1.1.1"), // rfc3279
    DSA("DSA", "1.2.840.10040.4.1"), // rfc3279
    DH("Diffie-Hellman", "1.2.840.10046.2.1"), // rfc3279
    KEA("Key Exchange Algorithm", "2.16.840.1.101.2.1.1.22"), // rfc3279
    ECDH_ECDSA("Elliptic Curve", "1.2.840.10045.2.1"), // rfc3279, used for ECDH and ECDSA
    RSASSA_PSS("RSA-PSS", "1.2.840.113549.1.1.10"), // rfc4055
    RSAES_OAEP("RSA-OAEP", "1.2.840.113549.1.1.7"), // rfc4055
    GOST_R3411_94("GOST_R3411_94", "1.2.643.2.2.20"), // RFC 4491
    GOST_R3411_2001("GOST_R3411_2001", "1.2.643.2.2.19"), // RFC 4491
    ECDH_ONLY("ECDH", "1.3.132.1.12"), // rfc5480
    ECMQV("ECMQV", "1.3.132.1.13"), // rfc5480
    X25519("X25519", "1.3.101.110"), // rfc8410
    X448("X448", "1.3.101.111"), // rfc8410
    ED25519("Ed25519", "1.3.101.112"), // rfc8410
    ED448("Ed448", "1.3.101.113"); // rfc8410

    private static final Map<String, X509PublicKeyType> oidMap = new HashMap<>();

    static {
        for (X509PublicKeyType algorithm : values()) {
            oidMap.put(algorithm.getOid().toString(), algorithm);
        }
    }

    private final String humanReadableName;
    private final ObjectIdentifier oid;

    private X509PublicKeyType(String humanReadableName, String oid) {
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

}
