/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model.publickey.parameters;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.handler.publickey.parameters.X509DssParametersHandler;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.parser.publickey.parameters.X509DssParametersParser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.publickey.parameters.X509DssParametersPreparator;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
import de.rub.nds.x509attacker.x509.serializer.publickey.parameters.X509DssParametersSerializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509DssParameters extends Asn1Sequence implements PublicParameters {

    private Asn1Integer p;
    private Asn1Integer q;
    private Asn1Integer g;

    private X509DssParameters() {
        super(null);
    }

    public X509DssParameters(String identifier) {
        super(identifier);
        this.p = new Asn1Integer("p");
        this.q = new Asn1Integer("q");
        this.g = new Asn1Integer("g");
        addChild(p);
        addChild(q);
        addChild(g);
    }

    public Asn1Integer getP() {
        return p;
    }

    public void setP(Asn1Integer p) {
        this.p = p;
    }

    public Asn1Integer getQ() {
        return q;
    }

    public void setQ(Asn1Integer q) {
        this.q = q;
    }

    public Asn1Integer getG() {
        return g;
    }

    public void setG(Asn1Integer g) {
        this.g = g;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new X509DssParametersHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new X509DssParametersParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new X509DssParametersPreparator(chooser, this);
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        return new X509DssParametersSerializer(chooser, this);
    }
}
