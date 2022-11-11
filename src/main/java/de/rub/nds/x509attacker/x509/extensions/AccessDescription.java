/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * AccessDescription ::= SEQUENCE { accessMethod OBJECT IDENTIFIER, accessLocation GeneralName }
 */
public class AccessDescription extends Asn1Sequence {

    private static final Logger LOGGER = LogManager.getLogger();

    private Asn1ObjectIdentifier accessMethod;
    private GeneralName accessLocation;

    public AccessDescription(String identifier) {
        super(identifier);
    }

    public Asn1ObjectIdentifier getAccessMethod() {
        return accessMethod;
    }

    public void setAccessMethod(Asn1ObjectIdentifier accessMethod) {
        this.accessMethod = accessMethod;
    }

    public GeneralName getAccessLocation() {
        return accessLocation;
    }

    public void setAccessLocation(GeneralName accessLocation) {
        this.accessLocation = accessLocation;
    }
}
