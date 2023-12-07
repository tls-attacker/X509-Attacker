/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model.publickey;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.handler.publickey.X509RsaPublicKeyHandler;
import de.rub.nds.x509attacker.x509.model.X509Component;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.parser.publickey.X509RsaPublicKeyParser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.publickey.X509RsaPublicKeyPreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509RsaPublicKey extends Asn1Sequence implements PublicKeyContent, X509Component {

    private Asn1Integer modulus;
    private Asn1Integer publicExponent;

    private X509RsaPublicKey() {
        super(null);
    }

    public X509RsaPublicKey(String identifier) {
        super(identifier);
        this.modulus = new Asn1Integer("modulus");
        this.publicExponent = new Asn1Integer("publicExponent");
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
        return new X509RsaPublicKeyHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new X509RsaPublicKeyParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new X509RsaPublicKeyPreparator(chooser, this);
    }

    @Override
    public X509PublicKeyType getX509PublicKeyType() {
        return X509PublicKeyType.RSA;
    }

    @Override
    public void prepare(X509Chooser chooser) {
        getPreparator(chooser).prepare();
    }

    @Override
    public byte[] getEncoded(X509Chooser chooser) {
        return getSerializer(chooser).serialize();
    }

    @Override
    public void adjustInContext(X509Chooser chooser) {
        getHandler(chooser).adjustContextAfterParse();
    }

    @Override
    public void readIn(X509Chooser chooser, byte[] bytesToRead) {
        getParser(chooser).parse(new BufferedInputStream(new ByteArrayInputStream(bytesToRead)));
    }
}
