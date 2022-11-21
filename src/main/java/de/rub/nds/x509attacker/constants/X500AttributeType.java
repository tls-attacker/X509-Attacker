/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.constants;

import de.rub.nds.x509attacker.oid.ObjectIdentifier;
import de.rub.nds.x509attacker.signatureengine.keyparsers.SignatureKeyType;
import java.util.HashMap;
import java.util.Map;

public enum X500AttributeType {

    /**
     * https://www.alvestrand.no/objectid/2.5.4.html
     */
    COMMON_NAME("commonName", "2.5.4.3"),
    COUNTRY_NAME("country", "2.5.4.6"),
    LOCALITY("locality", "2.5.4.7"),
    STATE_OR_PROVINCE_NAME("state", "2.5.4.8"),
    ORGANISATION_NAME("organisation", "2.5.4.10"),
    ORGANISATION_UNIT_NAME("organisation unit", "2.5.4.11");

    private static final Map<String, X500AttributeType> oidMap = new HashMap<>();

    static {
        for (X500AttributeType algorithm : values()) {
            oidMap.put(algorithm.getOid().toString(), algorithm);
        }
    }

    private final String humanReadableName;
    private final ObjectIdentifier oid;

    private X500AttributeType(String humanReadableName, String oid) {
        this.humanReadableName = humanReadableName;
        this.oid = new ObjectIdentifier(oid);
    }

    public String getHumanReadableName() {
        return humanReadableName;
    }

    public ObjectIdentifier getOid() {
        return oid;
    }

    public static X500AttributeType decodeFromOidBytes(byte[] oidBytes) {
        ObjectIdentifier objectIdentifier = new ObjectIdentifier(oidBytes);
        return oidMap.get(objectIdentifier.toString());
    }
}
