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
import de.rub.nds.x509attacker.x509.model.Extension;
import de.rub.nds.x509attacker.x509.model.extensions.BasicConstraints;
import de.rub.nds.x509attacker.x509.model.extensions.Unknown;

import java.util.HashMap;
import java.util.Map;

public enum X509ExtensionType {

    // https://www.alvestrand.no/objectid/2.5.29.html

    OLD_AUTHORITY_KEY_IDENTIFIER("2.5.29.1"),
    OLD_PRIMARY_KEY_ATTRIBUTES("2.5.29.2"),
    CERTIFICATE_POLICIES("2.5.29.3"),
    PRIMARY_KEY_USAGE_RESTRICTION("2.5.29.4"),
    SUBJECT_DIRECTORY_ATTRIBUTES("2.5.29.9"),
    SUBJECT_KEY_IDENTIFIER("2.5.29.14"),
    KEY_USAGE("2.5.29.15"),
    PRIVATE_KEY_USAGE_PERIOD("2.5.29.16"),
    SUBJECT_ALTERNATIVE_NAME("2.5.29.17"),
    ISSUER_ALTERNATIVE_NAME("2.5.29.18"),
    BASIC_CONSTRAINTS("2.5.29.19"),
    CRL_NUMBER("2.5.29.20"),
    REASON_CODE("2.5.29.21"),
    HOLD_INSTRUCTION_CODE("2.5.29.23"),
    INVALIDITY_DATE("2.5.29.24"),
    DELTA_CRL_INDICATOR("2.5.29.27"),
    ISSUING_DISTRIBUTION_POINT("2.5.29.28"),
    CERTIFICATE_ISSUER("2.5.29.29"),
    NAME_CONSTRAINTS("2.5.29.30"),
    CRL_DISTRIBUTION_POINTS("2.5.29.31"),
    CERTIFICATE_POLICIES_2("2.5.29.32"),
    POLICY_MAPPINGS("2.5.29.33"),
    AUTHORITY_KEY_IDENTIFIER("2.5.29.35"),
    POLICY_CONSTRAINTS("2.5.29.36"),
    EXTENDED_KEY_USAGE("2.5.29.37"),
    FRESHEST_CRL("2.5.29.46"),
    INHIBIT_ANY_POLICY("2.5.29.54"),

    // external
    AUTHORITY_INFORMATION_ACCESS("1.3.6.1.5.5.7.1.1"),
    OCSP_NO_CHECK("1.3.6.1.5.5.7.48.1.5"),
    NETSCAPE_CERTIFICATE_TYPE("2.16.840.1.113730.1.1");

    private static final Map<String, X509ExtensionType> oidMap = new HashMap<>();

    static {
        for (X509ExtensionType algorithm : values()) {
            oidMap.put(algorithm.getOid().toString(), algorithm);
        }
    }

    private final ObjectIdentifier oid;

    private X509ExtensionType(String oid) {
        this.oid = new ObjectIdentifier(oid);
    }

    public ObjectIdentifier getOid() {
        return oid;
    }

    public static X509ExtensionType decodeFromOidBytes(byte[] oidBytes) {
        ObjectIdentifier objectIdentifier = new ObjectIdentifier(oidBytes);
        return oidMap.get(objectIdentifier.toString());
    }

    public Extension generateExtension() {
        switch (this) {
            case BASIC_CONSTRAINTS:
                return new BasicConstraints("basicConstraints");
            default:
                // TODO: return explicit unknown extension?
                return new Unknown("UnknownExtension");
        }
    }
}
