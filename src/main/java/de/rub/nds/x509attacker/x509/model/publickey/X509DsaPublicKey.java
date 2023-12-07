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
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.handler.publickey.X509DsaPublicKeyHandler;
import de.rub.nds.x509attacker.x509.model.X509Component;
import de.rub.nds.x509attacker.x509.parser.X509Asn1IntegerParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.publickey.X509DsaPublicKeyPreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509DsaPublicKey extends Asn1Integer implements PublicKeyContent, X509Component {

    public X509DsaPublicKey() {
        super("y");
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new X509DsaPublicKeyHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new X509Asn1IntegerParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new X509DsaPublicKeyPreparator(this, chooser);
    }

    @Override
    public X509PublicKeyType getX509PublicKeyType() {
        return X509PublicKeyType.DSA;
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
