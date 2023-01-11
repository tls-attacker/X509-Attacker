/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.constants;

import static de.rub.nds.x509attacker.constants.X500AttributeType.values;

import de.rub.nds.asn1.oid.ObjectIdentifier;
import java.util.HashMap;
import java.util.Map;

public enum X509NamedCurve {
    SECP192R1("1.2.840.10045.3.1.1", 192),
    SECT163K1("1.3.132.0.1", 163),
    SECT163R2("1.3.132.0.15", 163),
    SECP224R1("1.3.132.0.33", 224),
    SECT233K1("1.3.132.0.26", 233),
    SECT233R1("1.3.132.0.27", 233),
    SECP256R1("1.2.840.10045.3.1.7", 256),
    SECT283K1("1.3.132.0.16", 283),
    SECT283R1("1.3.132.0.17", 283),
    SECP384R1("1.3.132.0.34", 384),
    SECT409K1("1.3.132.0.36", 409),
    SECT409R1("1.3.132.0.37", 409),
    SECP521R1("1.3.132.0.35", 521),
    SECT571K1("1.3.132.0.38", 571),
    SECT571R1("1.3.132.0.39", 571);

    private static final Map<String, X509NamedCurve> oidMap = new HashMap<>();

    static {
        for (X509NamedCurve curve : values()) {
            oidMap.put(curve.getOid().toString(), curve);
        }
    }

    private final ObjectIdentifier oid;

    private int bitLength;

    private int byteLength;

    private X509NamedCurve(String oid, int bitLength) {
        this.oid = new ObjectIdentifier(oid);
        this.bitLength = bitLength;
        this.byteLength = computeByteLength();
    }

    private int computeByteLength() {
        return (int) Math.ceil(((double) bitLength) / 8);
    }

    public int getBitLength() {
        return bitLength;
    }

    public void setBitLength(int bitLength) {
        this.bitLength = bitLength;
    }

    public int getByteLength() {
        return byteLength;
    }

    public void setByteLength(int byteLength) {
        this.byteLength = byteLength;
    }

    public ObjectIdentifier getOid() {
        return oid;
    }

    public static X509NamedCurve decodeFromOidBytes(byte[] oidBytes) {
        ObjectIdentifier objectIdentifier = new ObjectIdentifier(oidBytes);
        return oidMap.get(objectIdentifier.toString());
    }
}
