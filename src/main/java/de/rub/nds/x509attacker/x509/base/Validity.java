/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.handler.EmptyHandler;
import de.rub.nds.asn1.handler.Handler;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/** Validity ::= SEQUENCE { notBefore Time, notAfter Time } */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Validity extends Asn1Sequence<X509Chooser> {

    @HoldsModifiableVariable private Time notBefore;

    @HoldsModifiableVariable private Time notAfter;

    private Validity() {
        super(null);
    }

    public Validity(String identifier) {
        super(identifier);
        notBefore = new Time("notBefore");
        notAfter = new Time("notAfter");
        addChild(notBefore);
        addChild(notAfter);
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
    public Handler getHandler(X509Chooser chooser) {
        return new EmptyHandler(chooser);
    }
}
