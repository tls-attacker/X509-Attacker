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
    SECP112R1("1.3.132.0.6", 112),
    SECP112R2("1.3.132.0.7", 112),
    SECP128R1("1.3.132.0.28", 128),
    SECP128R2("1.3.132.0.29", 128),
    SECP160K1("1.3.132.0.9", 160),
    SECP160R1("1.3.132.0.8", 160),
    SECP160R2("1.3.132.0.30", 160),
    SECP192R1("1.2.840.10045.3.1.1", 192),
    SECP192K1("1.3.132.0.31", 192),
    SECP224K1("1.3.132.0.32", 224),
    SECP224R1("1.3.132.0.33", 224),
    SECP256R1("1.2.840.10045.3.1.7", 256),
    SECP256K1("1.3.132.0.10", 256),
    SECP384R1("1.3.132.0.34", 384),
    SECP521R1("1.3.132.0.35", 521),

    SECT113R1("1.3.132.0.4", 113),
    SECT113R2("1.3.132.0.5", 113),
    SECT131R1("1.3.132.0.22", 131),
    SECT131R2("1.3.132.0.23", 131),
    SECT163K1("1.3.132.0.1", 163),
    SECT163R1("1.3.132.0.2", 163),
    SECT163R2("1.3.132.0.15", 163),
    SECT193R1("1.3.132.0.24", 193),
    SECT193R2("1.3.132.0.25", 193),
    SECT233K1("1.3.132.0.26", 233),
    SECT233R1("1.3.132.0.27", 233),
    SECT239K1("1.3.132.0.3", 239),
    SECT283K1("1.3.132.0.16", 283),
    SECT283R1("1.3.132.0.17", 283),
    SECT409K1("1.3.132.0.36", 409),
    SECT409R1("1.3.132.0.37", 409),
    SECT571K1("1.3.132.0.38", 571),
    SECT571R1("1.3.132.0.39", 571),

    BRAINPOOLP160R1("1.3.36.3.3.2.8.1.1.1", 160),
    BRAINPOOLP160T1("1.3.36.3.3.2.8.1.1.2", 160),
    BRAINPOOLP192R1("1.3.36.3.3.2.8.1.1.3", 192),
    BRAINPOOLP192T1("1.3.36.3.3.2.8.1.1.4", 192),
    BRAINPOOLP224R1("1.3.36.3.3.2.8.1.1.5", 224),
    BRAINPOOLP224T1("1.3.36.3.3.2.8.1.1.6", 224),
    BRAINPOOLP256R1("1.3.36.3.3.2.8.1.1.7", 256),
    BRAINPOOLP256T1("1.3.36.3.3.2.8.1.1.8", 256),
    BRAINPOOLP320R1("1.3.36.3.3.2.8.1.1.9", 320),
    BRAINPOOLP320T1("1.3.36.3.3.2.8.1.1.10", 320),
    BRAINPOOLP384R1("1.3.36.3.3.2.8.1.1.11", 384),
    BRAINPOOLP384T1("1.3.36.3.3.2.8.1.1.12", 384),
    BRAINPOOLP512R1("1.3.36.3.3.2.8.1.1.13", 512),
    BRAINPOOLP512T1("1.3.36.3.3.2.8.1.1.14", 512);

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
