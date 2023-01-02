/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Boolean;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;

/**
 * Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE, extnValue
 * OCTET STRING -- contains the DER encoding of an ASN.1 value -- corresponding to the extension
 * type identified -- by extnID }
 */
public class Extension extends Asn1Sequence {

    @HoldsModifiableVariable private Asn1ObjectIdentifier extnID;

    @HoldsModifiableVariable private Asn1Boolean critical;

    @HoldsModifiableVariable private Asn1PrimitiveOctetString extnValue;

    public Extension(String identifier) {
        super(identifier);
        extnID = new Asn1ObjectIdentifier("extensionId");
        critical = new Asn1Boolean("critical");
        critical.setOptional(true);
        extnValue = new Asn1PrimitiveOctetString("extensionValue");
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
}
