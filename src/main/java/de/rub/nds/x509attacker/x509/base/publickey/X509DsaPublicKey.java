/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base.publickey;

import de.rub.nds.asn1.handler.Handler;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.publickey.X509DsaPublicKeyHandler;
import de.rub.nds.x509attacker.x509.preparator.publickey.X509DsaPublicKeyPreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.math.BigInteger;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509DsaPublicKey extends PublicKeyContent {

    private Asn1Integer<X509Chooser> publicKeyY;

    public X509DsaPublicKey() {
        super("dsaPublicKey");
        publicKeyY = new Asn1Integer<>("y");
    }

    @Override
    public Asn1FieldSerializer getSerializer() {
        return publicKeyY.getSerializer();
    }

    @Override
    public X509DsaPublicKeyPreparator getPreparator(X509Chooser chooser) {
        return new X509DsaPublicKeyPreparator(this, chooser);
    }

    public Asn1Integer<X509Chooser> getPublicKeyY() {
        return publicKeyY;
    }

    public void setPublicKeyY(Asn1Integer<X509Chooser> publicKeyY) {
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
    public Asn1Parser<?, ?> getParser(X509Chooser chooser) {
        return publicKeyY.getParser(chooser);
    }

    @Override
    public boolean isCompatible(Integer tagNumber, Boolean constructed, Integer classType) {
        return publicKeyY.isCompatible(tagNumber, constructed, classType);
    }

    @Override
    public Handler getHandler(X509Chooser chooser) {
        return new X509DsaPublicKeyHandler(chooser, this);
    }
}
