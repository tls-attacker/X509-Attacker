/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base.publickey.parameters;

import de.rub.nds.asn1.model.Asn1BitString;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.publickey.parameters.DhValidationParmsHandler;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509DhValidationParms extends Asn1Sequence implements PublicParameters {

    private Asn1BitString seed;
    private Asn1Integer pgenCounter;

    private X509DhValidationParms() {
        super(null);
    }

    public X509DhValidationParms(String identifier) {
        super(identifier);
        seed = new Asn1BitString("seed");
        pgenCounter = new Asn1Integer("pgenCounter");
        addChild(seed);
        addChild(pgenCounter);
    }

    public Asn1BitString getSeed() {
        return seed;
    }

    public void setSeed(Asn1BitString seed) {
        this.seed = seed;
    }

    public Asn1Integer getPgenCounter() {
        return pgenCounter;
    }

    public void setPgenCounter(Asn1Integer pgenCounter) {
        this.pgenCounter = pgenCounter;
    }

    @Override
    public Handler getHandler(X509Chooser chooser) {
        return new DhValidationParmsHandler(chooser, this);
    }
}
