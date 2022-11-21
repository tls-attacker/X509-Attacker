/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * PolicyQualifierInfo ::= SEQUENCE { policyQualifierId PolicyQualifierId, qualifier ANY DEFINED BY policyQualifierId }
 * }
 */
public class PolicyQualifierInfo extends Asn1Sequence {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable
    private Asn1ObjectIdentifier policyQualifierId; // PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps |
    // id-qt-unotice )
    @HoldsModifiableVariable
    private Asn1Encodable qualifier;

    public PolicyQualifierInfo(String identifier) {
        super(identifier);
        policyQualifierId = new Asn1ObjectIdentifier("policyQualifiersId");
        qualifier = new Asn1Null("qualifier");
        addChild(policyQualifierId);
        addChild(qualifier);
    }

    public Asn1ObjectIdentifier getPolicyQualifierId() {
        return policyQualifierId;
    }

    public void setPolicyQualifierId(Asn1ObjectIdentifier policyQualifierId) {
        this.policyQualifierId = policyQualifierId;
    }

    public Asn1Encodable getQualifier() {
        return qualifier;
    }

    public void setQualifier(Asn1Encodable qualifier) {
        this.qualifier = qualifier;
    }
}
