/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base.publickey;

import java.math.BigInteger;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.handler.publickey.X509DsaPublicKeyHandler;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.publickey.X509DsaPublicKeyPreparator;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509DsaPublicKey extends PublicKeyContent {

    private Asn1Integer publicKeyY;

    public X509DsaPublicKey() {
        super("dsaPublicKey");
        publicKeyY = new Asn1Integer("y");
    }

    public Asn1Integer getPublicKeyY() {
        return publicKeyY;
    }

    public void setPublicKeyY(Asn1Integer publicKeyY) {
        this.publicKeyY = publicKeyY;
    }

    public void setY(BigInteger y) {
        publicKeyY.setValue(y);
    }

    public BigInteger getY() {
        return publicKeyY.getValue().getValue();
    }

    @Override
    public boolean isEllipticCurve() {
        return false;
    }

    @Override
    public boolean isCompatible(Integer tagNumber, Boolean constructed, Integer classType) {
        return publicKeyY.isCompatible(tagNumber, constructed, classType);
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new X509DsaPublicKeyHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return publicKeyY.getParser(chooser);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new X509DsaPublicKeyPreparator(this, chooser);
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        return publicKeyY.getSerializer();
    }
}
