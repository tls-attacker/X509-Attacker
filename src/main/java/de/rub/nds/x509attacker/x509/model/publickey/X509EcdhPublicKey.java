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
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.handler.publickey.X509EcdhPublicKeyHandler;
import de.rub.nds.x509attacker.x509.parser.X509Asn1OctetStringParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.publickey.X509EcdhPublicKeyPreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509EcdhPublicKey extends Asn1OctetString implements PublicKeyContent {

    private ModifiableBigInteger xCoordinate;
    private ModifiableBigInteger yCoordinate;

    private ModifiableByte formatByte;

    public X509EcdhPublicKey() {
        super("ECPoint");
    }

    public ModifiableBigInteger getxCoordinate() {
        return xCoordinate;
    }

    public void setxCoordinate(ModifiableBigInteger xCoordinate) {
        this.xCoordinate = xCoordinate;
    }

    public ModifiableBigInteger getyCoordinate() {
        return yCoordinate;
    }

    public void setyCoordinate(ModifiableBigInteger yCoordinate) {
        this.yCoordinate = yCoordinate;
    }

    public ModifiableByte getFormatByte() {
        return formatByte;
    }

    public void setFormatByte(ModifiableByte formatByte) {
        this.formatByte = formatByte;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new X509EcdhPublicKeyHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new X509Asn1OctetStringParser(chooser, this); // TODO
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new X509EcdhPublicKeyPreparator(chooser, this);
    }

    @Override
    public X509PublicKeyType getX509PublicKeyType() {
        return X509PublicKeyType.ECDH_ONLY;
    }
}
