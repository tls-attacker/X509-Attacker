/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base.publickey.parameters;

import de.rub.nds.asn1.handler.Handler;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.handler.publickey.parameters.DhParametersHandler;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class DhParameters extends Asn1Sequence<X509Chooser> implements PublicParameters {

    private Asn1Integer p;
    // private Asn1Integer q;
    private Asn1Integer g;
    // private Asn1Integer j;
    private DhValidationParms validationParms;

    private DhParameters() {
        super(null);
    }

    public DhParameters(String identifier) {
        super(identifier);
        this.p = new Asn1Integer("p");
        // this.q = new Asn1Integer("q");
        this.g = new Asn1Integer("g");
        // this.j = new Asn1Integer("j");
        this.validationParms = new DhValidationParms("validationParms");
        validationParms.setOptional(true);
        addChild(p);
        // addChild(q);
        addChild(g);
        // addChild(j);
        addChild(validationParms);
    }

    public DhParameters(String identifier, X509CertificateConfig config) {
        super(identifier);
        this.p = new Asn1Integer("p");
        // this.q = new Asn1Integer("q");
        this.g = new Asn1Integer("g");
        // this.j = new Asn1Integer("j");
        if (config.getIncludeDhValidationParameters()) {
            this.validationParms = new DhValidationParms("validationParms");
        }
        addChild(p);
        // addChild(q);
        addChild(g);
        // addChild(j);
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

    //    public Asn1Integer getQ() {
    //        return q;
    //    }
    //
    //    public void setQ(Asn1Integer q) {
    //        this.q = q;
    //    }

    public Asn1Integer getG() {
        return g;
    }

    public void setG(Asn1Integer g) {
        this.g = g;
    }

    //    public Asn1Integer getJ() {
    //        return j;
    //    }
    //
    //    public void setJ(Asn1Integer j) {
    //        this.j = j;
    //    }

    public DhValidationParms getValidationParms() {
        return validationParms;
    }

    public void setValidationParms(DhValidationParms validationParms) {
        this.validationParms = validationParms;
    }

    @Override
    public Handler getHandler(X509Chooser chooser) {
        return new DhParametersHandler(chooser, this);
    }
}
