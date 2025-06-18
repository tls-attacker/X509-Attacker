/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.constants;

public enum ExtendedKeyUsage {
    CLIENT_AUTH("1.3.6.1.5.5.7.3.2"),
    CODE_SIGNING("1.3.6.1.5.5.7.3.3"),
    EMAIL_PROECTION("1.3.6.1.5.5.7.3.4"),
    OCSP_SIGNING("1.3.6.1.5.5.7.3.9"),
    SERVER_AUTH("1.3.6.1.5.5.7.3.1"),
    TIME_STAMPING("1.3.6.1.5.5.7.3.8"),
    SMART_CARD_LOGON("1.3.6.1.4.1.311.20.2.2"),
    IPSEC_IKE_INTERMEDIATE("1.3.6.1.5.5.8.2.2"),
    IPSEC_IKE("1.3.6.1.5.5.7.3.17"),
    SIGNING_KDC_RESPONSES("1.3.6.1.5.2.3.5"),
    IP_SECUREITY_USER("1.3.6.1.5.5.7.3.7"),
    ENCRYPTING_FILE_SYSTEM("1.3.6.1.4.1.311.10.3.4"),
    FILE_RECOVERY("1.3.6.1.4.1.311.10.3.4.1"),
    CERTIFICATE_TRUST_LIST_SIGNING("1.3.6.1.4.1.311.10.3.1"),
    MICROSOFT_SERVER_GATED_CRYPTO("1.3.6.1.4.1.311.10.3.3"),
    MICROSOFT_ENCRYPTED_FILE_SYSTEM("1.3.6.1.4.1.311.10.3.4"),
    NETSCAPE_SGC("2.16.840.1.113730.4.1");

    private String oid;

    ExtendedKeyUsage(String oid) {
        this.oid = oid;
    }

    public String getValue() {
        return oid;
    }
}
