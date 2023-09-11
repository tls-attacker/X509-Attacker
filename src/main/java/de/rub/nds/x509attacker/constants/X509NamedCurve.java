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
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import java.util.HashMap;
import java.util.Map;

public enum X509NamedCurve {
    SECP112R1("1.3.132.0.6", NamedEllipticCurveParameters.SECP112R1),
    SECP112R2("1.3.132.0.7", NamedEllipticCurveParameters.SECP112R2),
    SECP128R1("1.3.132.0.28", NamedEllipticCurveParameters.SECP128R1),
    SECP128R2("1.3.132.0.29", NamedEllipticCurveParameters.SECP128R2),
    SECP160K1("1.3.132.0.9", NamedEllipticCurveParameters.SECP160K1),
    SECP160R1("1.3.132.0.8", NamedEllipticCurveParameters.SECP160R1),
    SECP160R2("1.3.132.0.30", NamedEllipticCurveParameters.SECP160R2),
    SECP192R1("1.2.840.10045.3.1.1", NamedEllipticCurveParameters.SECP192R1),
    SECP192K1("1.3.132.0.31", NamedEllipticCurveParameters.SECP192K1),
    SECP224K1("1.3.132.0.32", NamedEllipticCurveParameters.SECP224K1),
    SECP224R1("1.3.132.0.33", NamedEllipticCurveParameters.SECP224R1),
    SECP256R1("1.2.840.10045.3.1.7", NamedEllipticCurveParameters.SECP256R1),
    SECP256K1("1.3.132.0.10", NamedEllipticCurveParameters.SECP256K1),
    SECP384R1("1.3.132.0.34", NamedEllipticCurveParameters.SECP384R1),
    SECP521R1("1.3.132.0.35", NamedEllipticCurveParameters.SECP521R1),
    SECT113R1("1.3.132.0.4", NamedEllipticCurveParameters.SECT113R1),
    SECT113R2("1.3.132.0.5", NamedEllipticCurveParameters.SECT113R2),
    SECT131R1("1.3.132.0.22", NamedEllipticCurveParameters.SECT131R1),
    SECT131R2("1.3.132.0.23", NamedEllipticCurveParameters.SECT131R2),
    SECT163K1("1.3.132.0.1", NamedEllipticCurveParameters.SECT163K1),
    SECT163R1("1.3.132.0.2", NamedEllipticCurveParameters.SECT163R1),
    SECT163R2("1.3.132.0.15", NamedEllipticCurveParameters.SECT163R2),
    SECT193R1("1.3.132.0.24", NamedEllipticCurveParameters.SECT193R1),
    SECT193R2("1.3.132.0.25", NamedEllipticCurveParameters.SECT193R2),
    SECT233K1("1.3.132.0.26", NamedEllipticCurveParameters.SECT233K1),
    SECT233R1("1.3.132.0.27", NamedEllipticCurveParameters.SECT233R1),
    SECT239K1("1.3.132.0.3", NamedEllipticCurveParameters.SECT239K1),
    SECT283K1("1.3.132.0.16", NamedEllipticCurveParameters.SECT283K1),
    SECT283R1("1.3.132.0.17", NamedEllipticCurveParameters.SECT283R1),
    SECT409K1("1.3.132.0.36", NamedEllipticCurveParameters.SECT409K1),
    SECT409R1("1.3.132.0.37", NamedEllipticCurveParameters.SECT409R1),
    SECT571K1("1.3.132.0.38", NamedEllipticCurveParameters.SECT571K1),
    SECT571R1("1.3.132.0.39", NamedEllipticCurveParameters.SECT571R1),
    BRAINPOOLP160R1("1.3.36.3.3.2.8.1.1.1", NamedEllipticCurveParameters.BRAINPOOLP160R1),
    BRAINPOOLP160T1("1.3.36.3.3.2.8.1.1.2", NamedEllipticCurveParameters.BRAINPOOLP160T1),
    BRAINPOOLP192R1("1.3.36.3.3.2.8.1.1.3", NamedEllipticCurveParameters.BRAINPOOLP192R1),
    BRAINPOOLP192T1("1.3.36.3.3.2.8.1.1.4", NamedEllipticCurveParameters.BRAINPOOLP192T1),
    BRAINPOOLP224R1("1.3.36.3.3.2.8.1.1.5", NamedEllipticCurveParameters.BRAINPOOLP224R1),
    BRAINPOOLP224T1("1.3.36.3.3.2.8.1.1.6", NamedEllipticCurveParameters.BRAINPOOLP224T1),
    BRAINPOOLP256R1("1.3.36.3.3.2.8.1.1.7", NamedEllipticCurveParameters.BRAINPOOLP256R1),
    BRAINPOOLP256T1("1.3.36.3.3.2.8.1.1.8", NamedEllipticCurveParameters.BRAINPOOLP256T1),
    BRAINPOOLP320R1("1.3.36.3.3.2.8.1.1.9", NamedEllipticCurveParameters.BRAINPOOLP320R1),
    BRAINPOOLP320T1("1.3.36.3.3.2.8.1.1.10", NamedEllipticCurveParameters.BRAINPOOLP320T1),
    BRAINPOOLP384R1("1.3.36.3.3.2.8.1.1.11", NamedEllipticCurveParameters.BRAINPOOLP384R1),
    BRAINPOOLP384T1("1.3.36.3.3.2.8.1.1.12", NamedEllipticCurveParameters.BRAINPOOLP384T1),
    BRAINPOOLP512R1("1.3.36.3.3.2.8.1.1.13", NamedEllipticCurveParameters.BRAINPOOLP512R1),
    BRAINPOOLP512T1("1.3.36.3.3.2.8.1.1.14", NamedEllipticCurveParameters.BRAINPOOLP512T1);

    private static final Map<String, X509NamedCurve> oidMap = new HashMap<>();

    static {
        for (X509NamedCurve curve : values()) {
            oidMap.put(curve.getOid().toString(), curve);
        }
    }

    private final ObjectIdentifier oid;

    private NamedEllipticCurveParameters parameters;

    private X509NamedCurve(String oid, NamedEllipticCurveParameters parameters) {
        this.oid = new ObjectIdentifier(oid);
        this.parameters = parameters;
    }

    public int getBitLength() {
        return parameters.getElementSizeBits();
    }

    public int getByteLength() {
        return parameters.getElementSizeBytes();
    }

    public ObjectIdentifier getOid() {
        return oid;
    }

    public static X509NamedCurve decodeFromOidBytes(byte[] oidBytes) {
        ObjectIdentifier objectIdentifier = new ObjectIdentifier(oidBytes);
        return oidMap.get(objectIdentifier.toString());
    }

    public NamedEllipticCurveParameters getParameters() {
        return parameters;
    }
}
