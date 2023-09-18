/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.asn1.model.Asn1Boolean;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1OctetString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
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
public class Extension extends Asn1Sequence implements X509Component {

    @HoldsModifiableVariable private Asn1ObjectIdentifier extnID;

    @HoldsModifiableVariable private Asn1Boolean critical;

    @HoldsModifiableVariable private Asn1OctetString extnValue;

    private Extension() {
        super(null);
    }

    public Extension(String identifier) {
        super(identifier);
        extnID = new Asn1ObjectIdentifier("extensionId");
        critical = new Asn1Boolean("critical");
        critical.setOptional(true);
        extnValue = new Asn1OctetString("extensionValue");
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

    public Asn1OctetString getExtnValue() {
        return extnValue;
    }

    public void setExtnValue(Asn1OctetString extnValue) {
        this.extnValue = extnValue;
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
}
