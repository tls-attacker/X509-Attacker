/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.TimeContextHint;
import de.rub.nds.x509attacker.x509.handler.ValidityHandler;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.ValidityParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.ValidityPreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.serializer.X509Asn1FieldSerializer;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/** Validity ::= SEQUENCE { notBefore Time, notAfter Time } */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Validity extends Asn1Sequence implements X509Component {

    @HoldsModifiableVariable private Time notBefore;

    @HoldsModifiableVariable private Time notAfter;

    private Validity() {
        this("validity");
    }

    public Validity(String identifier) {
        super(identifier);
        notBefore = new Time("notBefore", TimeContextHint.NOT_BEFORE);
        notAfter = new Time("notAfter", TimeContextHint.NOT_AFTER);
    }

    public Time getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(Time notBefore) {
        this.notBefore = notBefore;
    }

    public Time getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(Time notAfter) {
        this.notAfter = notAfter;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new ValidityHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new ValidityParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new ValidityPreparator(chooser, this);
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        return new X509Asn1FieldSerializer(this);
    }
}
