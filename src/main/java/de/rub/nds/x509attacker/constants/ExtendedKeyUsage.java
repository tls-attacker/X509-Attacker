/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.constants;

public enum ExtendedKeyUsage {
    CLIENT_AUTH(0),
    CODE_SIGNING(0),
    EMAIL_PROECTION(0),
    OCSP_SIGNING(0),
    SERVER_AUTH(0),
    TIME_STAMPING(0),
    SMART_CARD_LOGON(0),
    IPSEC_IKE_INTERMEDIATE(0),
    IPSEC_IKE(0),
    SIGNING_KDC_RESPONSES(0),
    IP_SECUREITY_USER(0),
    ENCRYPTING_FILE_SYSTEM(0),
    FILE_RECOVERY(0);

    private int value;

    private ExtendedKeyUsage(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
