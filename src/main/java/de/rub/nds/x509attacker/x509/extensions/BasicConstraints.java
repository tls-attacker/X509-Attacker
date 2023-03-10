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
import de.rub.nds.asn1.model.Asn1Boolean;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX)
 * OPTIONAL }
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class BasicConstraints extends Asn1Sequence<X509Chooser> {

    @HoldsModifiableVariable private Asn1Boolean<X509Chooser> ca;

    @HoldsModifiableVariable private Asn1Integer<X509Chooser> pathLenConstraint;

    private BasicConstraints() {
        super(null);
    }

    public BasicConstraints(String identifier) {
        super(identifier);
        ca = new Asn1Boolean<>("ca");
        pathLenConstraint = new Asn1Integer<>("pathLenConstraint");
        addChild(ca);
        addChild(pathLenConstraint);
    }

    public Asn1Boolean<X509Chooser> getCa() {
        return ca;
    }

    public void setCa(Asn1Boolean<X509Chooser> ca) {
        this.ca = ca;
    }

    public Asn1Integer<X509Chooser> getPathLenConstraint() {
        return pathLenConstraint;
    }

    public void setPathLenConstraint(Asn1Integer<X509Chooser> pathLenConstraint) {
        this.pathLenConstraint = pathLenConstraint;
    }

    @Override
    public Handler<X509Chooser> getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
