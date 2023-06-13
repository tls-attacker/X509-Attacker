/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base.publickey;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.X509Component;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509RsaPublicKeyContentSequence extends Asn1Sequence implements X509Component{

    private Asn1Integer modulus;
    private Asn1Integer publicExponent;

    private X509RsaPublicKeyContentSequence() {
        super(null);
    }

    public X509RsaPublicKeyContentSequence(String identifier) {
        super(identifier);
        this.modulus = new Asn1Integer("modulus");
        this.publicExponent = new Asn1Integer("publicExponent");
        addChild(this.modulus);
        addChild(this.publicExponent);
    }

    public Asn1Integer getModulus() {
        return modulus;
    }

    public void setModulus(Asn1Integer modulus) {
        this.modulus = modulus;
    }

    public Asn1Integer getPublicExponent() {
        return publicExponent;
    }

    public void setPublicExponent(Asn1Integer publicExponent) {
        this.publicExponent = publicExponent;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }
}
