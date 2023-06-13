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
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.handler.publickey.X509DhPublicKeyHandler;
import de.rub.nds.x509attacker.x509.parser.X509DhPublicKeyParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.publickey.X509DhPublicKeyPreparator;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509DhPublicKey extends PublicKeyContent {

    private Asn1Integer publicKey;

    public X509DhPublicKey() {
        super("dhPublicKey");
        publicKey = new Asn1Integer("publicKey");
    }

    public Asn1Integer getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(Asn1Integer publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new X509DhPublicKeyHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new X509DhPublicKeyParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new X509DhPublicKeyPreparator(chooser, this);
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        return publicKey.getSerializer();
    }

    @Override
    public boolean isEllipticCurve() {
        return false;
    }

    @Override
    public boolean isCompatible(Integer tagNumber, Boolean constructed, Integer classType) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
