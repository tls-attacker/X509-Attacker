/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.constants;

import java.math.BigInteger;

public enum X509Version {
    V1(new BigInteger("1")),
    V2(new BigInteger("2")),
    V3(new BigInteger("3"));

    private final BigInteger value;

    private X509Version(BigInteger value) {
        this.value = value;
    }

    public BigInteger getValue() {
        return value;
    }

}
