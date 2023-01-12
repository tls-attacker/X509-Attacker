/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.handler.Handler;
import de.rub.nds.asn1.model.Asn1Boolean;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE, extnValue
 * OCTET STRING -- contains the DER encoding of an ASN.1 value -- corresponding to the extension
 * type identified -- by extnID }
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Extension extends Asn1Sequence<X509Chooser> {

    @HoldsModifiableVariable private Asn1ObjectIdentifier<X509Chooser> extnID;

    @HoldsModifiableVariable private Asn1Boolean<X509Chooser> critical;

    @HoldsModifiableVariable private Asn1PrimitiveOctetString<X509Chooser> extnValue;

    private Extension() {
        super(null);
    }

    public Extension(String identifier) {
        super(identifier);
        extnID = new Asn1ObjectIdentifier<>("extensionId");
        critical = new Asn1Boolean<>("critical");
        critical.setOptional(true);
        extnValue = new Asn1PrimitiveOctetString<>("extensionValue");
        addChild(extnID);
        addChild(critical);
        addChild(extnValue);
    }

    public Asn1ObjectIdentifier getExtnID() {
        return extnID;
    }

    public void setExtnID(Asn1ObjectIdentifier extnID) {
        this.extnID = extnID;
    }

    public Asn1Boolean getCritical() {
        return critical;
    }

    public void setCritical(Asn1Boolean critical) {
        this.critical = critical;
    }

    public Asn1PrimitiveOctetString getExtnValue() {
        return extnValue;
    }

    public void setExtnValue(Asn1PrimitiveOctetString extnValue) {
        this.extnValue = extnValue;
    }

    @Override
    public Handler getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
