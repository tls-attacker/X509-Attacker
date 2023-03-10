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
import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.publickey.parameters.DhValidationParmsHandler;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509DhValidationParms extends Asn1Sequence<X509Chooser> implements PublicParameters {

    private Asn1PrimitiveBitString<X509Chooser> seed;
    private Asn1Integer<X509Chooser> pgenCounter;

    private X509DhValidationParms() {
        super(null);
    }

    public X509DhValidationParms(String identifier) {
        super(identifier);
        seed = new Asn1PrimitiveBitString<X509Chooser>("seed");
        pgenCounter = new Asn1Integer<X509Chooser>("pgenCounter");
        addChild(seed);
        addChild(pgenCounter);
    }

    public Asn1PrimitiveBitString<X509Chooser> getSeed() {
        return seed;
    }

    public void setSeed(Asn1PrimitiveBitString<X509Chooser> seed) {
        this.seed = seed;
    }

    public Asn1Integer<X509Chooser> getPgenCounter() {
        return pgenCounter;
    }

    public void setPgenCounter(Asn1Integer<X509Chooser> pgenCounter) {
        this.pgenCounter = pgenCounter;
    }

    @Override
    public Handler<X509Chooser> getHandler(X509Chooser chooser) {
        return new DhValidationParmsHandler(chooser, this);
    }
}
