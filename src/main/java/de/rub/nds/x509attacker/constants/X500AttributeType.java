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
import java.util.HashMap;
import java.util.Map;

public enum X500AttributeType {

    /** https://www.alvestrand.no/objectid/2.5.4.html */
    COMMON_NAME("commonName", "CN", "2.5.4.3"),
    COUNTRY_NAME("country", "C", "2.5.4.6"),
    LOCALITY("locality", "L", "2.5.4.7"),
    STATE_OR_PROVINCE_NAME("state", "S", "2.5.4.8"),
    ORGANISATION_NAME("organisation", "O", "2.5.4.10"),
    ORGANISATION_UNIT_NAME("organisation unit", "OU", "2.5.4.11");

    private static final Map<String, X500AttributeType> oidMap = new HashMap<>();

    static {
        for (X500AttributeType algorithm : values()) {
            oidMap.put(algorithm.getOid().toString(), algorithm);
        }
    }

    private final String humanReadableName;
    private final String shortString;
    private final ObjectIdentifier oid;

    private X500AttributeType(String humanReadableName, String shortString, String oid) {
        this.humanReadableName = humanReadableName;
        this.shortString = shortString;
        this.oid = new ObjectIdentifier(oid);
    }

    public String getHumanReadableName() {
        return humanReadableName;
    }

    public String getShortString() {
        return shortString;
    }

    public ObjectIdentifier getOid() {
        return oid;
    }

    public static X500AttributeType decodeFromOidBytes(byte[] oidBytes) {
        ObjectIdentifier objectIdentifier = new ObjectIdentifier(oidBytes);
        return oidMap.get(objectIdentifier.toString());
    }
}
