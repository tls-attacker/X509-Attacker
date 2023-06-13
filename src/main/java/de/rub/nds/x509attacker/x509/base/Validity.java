/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.time.TimeField;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.EmptyHandler;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/** Validity ::= SEQUENCE { notBefore Time, notAfter Time } */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Validity extends Asn1Sequence implements X509Component {

    @HoldsModifiableVariable
    private TimeField notBefore;

    @HoldsModifiableVariable
    private TimeField notAfter;

    private Validity() {
        super(null);
    }

    public Validity(String identifier) {
        super(identifier);
    }

    public TimeField getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(TimeField notBefore) {
        this.notBefore = notBefore;
    }

    public TimeField getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(TimeField notAfter) {
        this.notAfter = notAfter;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new EmptyHandler(chooser);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new ValidityParser(chooser);
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
