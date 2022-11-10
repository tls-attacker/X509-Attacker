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
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * PolicyQualifierInfo ::= SEQUENCE { policyQualifierId PolicyQualifierId, qualifier ANY DEFINED BY policyQualifierId }
 * }
 */
public class PolicyQualifierInfo extends Asn1Sequence {

    private static final Logger LOGGER = LogManager.getLogger();

    private Asn1ObjectIdentifier policyQualifierId; // PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps |
    // id-qt-unotice )
    private Asn1Encodable qualifier;

    public PolicyQualifierInfo(String identifier) {
        this.setIdentifier(identifier);
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
