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
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.handler.publickey.parameters.X509DhParametersHandler;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.parser.publickey.parameters.X509DhParametersParser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.publickey.parameters.X509DhParameterPreparator;
import de.rub.nds.x509attacker.x509.serializer.X509Asn1FieldSerializer;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509DhParameters extends Asn1Sequence implements PublicParameters {

    private Asn1Integer p;
    private Asn1Integer g;
    private Asn1Integer q;
    private Asn1Integer j;
    private X509DhValidationParms validationParms;

    private X509DhParameters() {
        super("dhParameters");
    }

    public X509DhParameters(String identifier) {
        super(identifier);
        this.p = new Asn1Integer("p");
        this.g = new Asn1Integer("g");
        this.q = new Asn1Integer("q");
        this.j = new Asn1Integer("j");

        this.validationParms = new X509DhValidationParms("validationParms");
        this.j.setOptional(true);
        this.validationParms.setOptional(true);
    }

    public X509DhParameters(String identifier, X509CertificateConfig config) {
        super(identifier);
        this.p = new Asn1Integer("p");
        this.g = new Asn1Integer("g");
        this.q = new Asn1Integer("q");
        this.j = new Asn1Integer("j");
        this.j.setOptional(true);
        if (config.getIncludeDhValidationParameters()) {
            this.validationParms = new X509DhValidationParms("validationParms");
        }
    }

    public Asn1Integer getP() {
        return p;
    }

    public void setP(Asn1Integer p) {
        this.p = p;
    }

    public Asn1Integer getG() {
        return g;
    }

    public void setG(Asn1Integer g) {
        this.g = g;
    }

    public Asn1Integer getQ() {
        return q;
    }

    public void setQ(Asn1Integer q) {
        this.q = q;
    }

    public Asn1Integer getJ() {
        return j;
    }

    public void setJ(Asn1Integer j) {
        this.j = j;
    }

    public X509DhValidationParms getValidationParms() {
        return validationParms;
    }

    public void setValidationParms(X509DhValidationParms validationParms) {
        this.validationParms = validationParms;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new X509DhParametersHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new X509DhParametersParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new X509DhParameterPreparator(chooser, this);
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        return new X509Asn1FieldSerializer(this);
    }
}
