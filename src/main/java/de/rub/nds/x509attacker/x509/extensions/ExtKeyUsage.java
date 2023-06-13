/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;

/**
 * ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 *
 * <p>KeyPurposeId ::= OBJECT IDENTIFIER
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ExtKeyUsage extends Asn1Sequence {

    @XmlElementWrapper @XmlElementRef @HoldsModifiableVariable
    private List<Asn1ObjectIdentifier> keyPurposeID;

    private ExtKeyUsage() {
        super(null);
    }

    private ExtKeyUsage(String identifier) {
        super(identifier);
        keyPurposeID = new LinkedList<>();
    }

    public List<Asn1ObjectIdentifier> getKeyPurposeID() {
        return keyPurposeID;
    }

    public void setKeyPurposeID(List<Asn1ObjectIdentifier> keyPurposeID) {
        this.keyPurposeID = keyPurposeID;
    }

    @Override
    public Handler getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
