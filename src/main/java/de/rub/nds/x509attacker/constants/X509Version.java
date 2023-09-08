/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.constants;

import java.math.BigInteger;

public enum X509Version {
    V1(new BigInteger("0")),
    V2(new BigInteger("1")),
    V3(new BigInteger("2"));

    private final BigInteger value;

    private X509Version(BigInteger value) {
        this.value = value;
    }

    public BigInteger getValue() {
        return value;
    }

    public static X509Version convert(BigInteger value) {
        for (X509Version version : values()) {
            if (version.getValue().equals(value)) {
                return version;
            }
        }
        return null;
    }
}
