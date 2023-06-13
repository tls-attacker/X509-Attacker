/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base.publickey.parameters;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.preparator.Preparator;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.base.X509Component;
import de.rub.nds.x509attacker.x509.handler.publickey.parameters.DhParametersHandler;
import de.rub.nds.x509attacker.x509.preparator.publickey.parameters.DhParameterPreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509DhParameters extends Asn1Sequence implements PublicParameters, X509Component {

    private Asn1Integer p;
    private Asn1Integer g;
    private X509DhValidationParms validationParms;

    private X509DhParameters() {
        super("dhParameters");
    }

    public X509DhParameters(String identifier) {
        super(identifier);
        this.p = new Asn1Integer("p");
        this.g = new Asn1Integer("g");
        this.validationParms = new X509DhValidationParms("validationParms");
        validationParms.setOptional(true);
        addChild(p);
        addChild(g);
        addChild(validationParms);
    }

    public X509DhParameters(String identifier, X509CertificateConfig config) {
        super(identifier);
        this.p = new Asn1Integer("p");
        this.g = new Asn1Integer("g");
        if (config.getIncludeDhValidationParameters()) {
            this.validationParms = new X509DhValidationParms("validationParms");
        }
        addChild(p);
        addChild(g);
        if (validationParms != null) {
            addChild(validationParms);
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

    public X509DhValidationParms getValidationParms() {
        return validationParms;
    }

    public void setValidationParms(X509DhValidationParms validationParms) {
        this.validationParms = validationParms;
    }

    @Override
    public Handler getHandler(X509Chooser chooser) {
        return new DhParametersHandler(chooser, this);
    }

    @Override
    public Preparator getPreparator(X509Chooser chooser) {
        return new DhParameterPreparator(chooser, this);
    }
}
