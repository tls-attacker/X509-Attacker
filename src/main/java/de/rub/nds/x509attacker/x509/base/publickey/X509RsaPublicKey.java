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
import de.rub.nds.asn1.preparator.Preparator;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.publickey.X509RsaPublicKeyHandler;
import de.rub.nds.x509attacker.x509.parser.X509RsaPublicKeyParser;
import de.rub.nds.x509attacker.x509.preparator.publickey.X509RsaPublicKeyPreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509RsaPublicKey extends PublicKeyContent {

    private X509RsaPublicKeyContentSequence rsaPublicKeyContentSequence;

    public X509RsaPublicKey() {
        super("rsaPublicKey");
        rsaPublicKeyContentSequence = new X509RsaPublicKeyContentSequence("rsaPublicKeyContent");
    }

    public X509RsaPublicKeyContentSequence getRsaPublicKeyContentSequence() {
        return rsaPublicKeyContentSequence;
    }

    public void setRsaPublicKeyContentSequence(
            X509RsaPublicKeyContentSequence rsaPublicKeyContentSequence) {
        this.rsaPublicKeyContentSequence = rsaPublicKeyContentSequence;
    }

    @Override
    public Asn1FieldSerializer getSerializer() {
        return rsaPublicKeyContentSequence.getSerializer();
    }

    @Override
    public Preparator getPreparator(X509Chooser chooser) {
        return new X509RsaPublicKeyPreparator(chooser, this);
    }

    @Override
    public boolean isEllipticCurve() {
        return false;
    }

    @Override
    public X509RsaPublicKeyParser getParser(X509Chooser chooser) {
        return new X509RsaPublicKeyParser(chooser, this);
    }

    @Override
    public boolean isCompatible(Integer tagNumber, Boolean constructed, Integer classType) {
        return rsaPublicKeyContentSequence.isCompatible(tagNumber, constructed, classType);
    }

    @Override
    public Handler<X509Chooser> getHandler(X509Chooser chooser) {
        return new X509RsaPublicKeyHandler(chooser, this);
    }
}
