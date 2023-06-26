/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model.publickey.parameters;

import de.rub.nds.asn1.model.Asn1BitString;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.handler.publickey.parameters.X509DhValidationParmsHandler;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.parser.publickey.parameters.X509DhValidationParmsParser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.publickey.parameters.X509DhValidationParmsPreparator;
import de.rub.nds.x509attacker.x509.serializer.X509Asn1FieldSerializer;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
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
    public X509Handler getHandler(X509Chooser chooser) {
        return new X509DhValidationParmsHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new X509DhValidationParmsParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new X509DhValidationParmsPreparator(chooser, this);
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        return new X509Asn1FieldSerializer(this);
    }
}
