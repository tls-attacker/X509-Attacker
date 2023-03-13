/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.handler.Handler;
import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * PolicyQualifierInfo ::= SEQUENCE { policyQualifierId PolicyQualifierId, qualifier ANY DEFINED BY
 * policyQualifierId } }
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class PolicyQualifierInfo extends Asn1Sequence<X509Chooser> {

    @HoldsModifiableVariable
    private Asn1ObjectIdentifier<X509Chooser>
            policyQualifierId; // PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps |
    // id-qt-unotice )
    @HoldsModifiableVariable private Asn1Encodable<X509Chooser> qualifier;

    private PolicyQualifierInfo() {
        super(null);
    }

    public PolicyQualifierInfo(String identifier) {
        super(identifier);
        policyQualifierId = new Asn1ObjectIdentifier<>("policyQualifiersId");
        qualifier = new Asn1Null<>("qualifier");
        addChild(policyQualifierId);
        addChild(qualifier);
    }

    public Asn1ObjectIdentifier<X509Chooser> getPolicyQualifierId() {
        return policyQualifierId;
    }

    public void setPolicyQualifierId(Asn1ObjectIdentifier<X509Chooser> policyQualifierId) {
        this.policyQualifierId = policyQualifierId;
    }

    public Asn1Encodable<X509Chooser> getQualifier() {
        return qualifier;
    }

    public void setQualifier(Asn1Encodable<X509Chooser> qualifier) {
        this.qualifier = qualifier;
    }

    @Override
    public Handler<X509Chooser> getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
