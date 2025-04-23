/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model.extensions;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.model.X509Component;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAnyElement;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * PolicyQualifierInfo ::= SEQUENCE { policyQualifierId PolicyQualifierId, qualifier ANY DEFINED BY
 * policyQualifierId } }
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class PolicyQualifierInfo extends Asn1Sequence implements X509Component {

    @HoldsModifiableVariable
    private Asn1ObjectIdentifier
            policyQualifierId; // PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps |

    // id-qt-unotice )
    @HoldsModifiableVariable
    @XmlAnyElement(lax = true)
    private Asn1Encodable qualifier;

    private PolicyQualifierInfo() {
        super(null);
    }

    public PolicyQualifierInfo(String identifier) {
        super(identifier);
        policyQualifierId = new Asn1ObjectIdentifier("policyQualifiersId");
        qualifier = new Asn1Null("qualifier");
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

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }
}
