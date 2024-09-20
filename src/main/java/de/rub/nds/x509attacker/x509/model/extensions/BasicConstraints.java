/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model.extensions;

import de.rub.nds.asn1.model.Asn1Boolean;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1UnknownSequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.extension.BasicConstraintsConfig;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.handler.extension.BasicConstraintsHandler;
import de.rub.nds.x509attacker.x509.model.Extension;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.parser.extension.BasicConstraintsParser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.extension.BasicConstraintsPreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER (0..MAX)
 * OPTIONAL }
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class BasicConstraints extends Extension<BasicConstraintsConfig> {

    // holds ca and pathlenconstraint
    @HoldsModifiableVariable private Asn1UnknownSequence wrappingSequence;

    @HoldsModifiableVariable private Asn1Boolean ca;

    @HoldsModifiableVariable private Asn1Integer pathLenConstraint;

    private BasicConstraints() {
        super(null);
    }

    public BasicConstraints(String identifier) {
        super(identifier);
        ca = new Asn1Boolean("ca");
        pathLenConstraint = new Asn1Integer("pathLenConstraint");
        wrappingSequence = new Asn1UnknownSequence("wrappingSequence");
    }

    public Asn1Boolean getCa() {
        return ca;
    }

    public void setCa(Asn1Boolean ca) {
        this.ca = ca;
    }

    public Asn1Integer getPathLenConstraint() {
        return pathLenConstraint;
    }

    public void setPathLenConstraint(Asn1Integer pathLenConstraint) {
        this.pathLenConstraint = pathLenConstraint;
    }

    public Asn1UnknownSequence getWrappingSequence() {
        return wrappingSequence;
    }

    public void setWrappingSequence(Asn1UnknownSequence wrappingSequence) {
        this.wrappingSequence = wrappingSequence;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new BasicConstraintsHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new BasicConstraintsParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser, BasicConstraintsConfig config) {
        return new BasicConstraintsPreparator(chooser, this, config);
    }
}
