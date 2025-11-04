/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model.publickey;

import de.rub.nds.asn1.model.Asn1OctetString;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.handler.publickey.X509Ed448PublicKeyHandler;
import de.rub.nds.x509attacker.x509.model.X509Component;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Ed448PublicKey extends Asn1OctetString implements PublicKeyContent, X509Component {

    public X509Ed448PublicKey() {
        super("ed448PublicKey");
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new X509Ed448PublicKeyHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new de.rub.nds.x509attacker.x509.parser.publickey.X509Ed448PublicKeyParser(
                chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new de.rub.nds.x509attacker.x509.preparator.publickey.Ed448PublicKeyPreparator(
                chooser, this);
    }

    @Override
    public X509PublicKeyType getX509PublicKeyType() {
        return X509PublicKeyType.ED448;
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
