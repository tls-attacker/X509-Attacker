/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.constants;

public enum KeyUsage {
    DIGITAL_SIGNATURE(128),
    NON_REPUDIATION(64),
    KEY_ENCIPHERMENT(32),
    DATA_ENCIPHERMENT(16),
    KEY_AGREEMENT(8),
    KEY_CERT_SIGN(4),
    CRL_SIGN(2),
    ENCIPHERMENT_ONLY(1),
    DECIPHERMENT_ONLY(32768);

    private int value;

    KeyUsage(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
