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
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.handler.publickey.X509EcdhEcdsaPublicKeyHandler;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.parser.publickey.X509EcdhEcdsaPublicKeyParser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.publickey.X509EcdhEcdsaPublicKeyPreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.math.BigInteger;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509EcdhEcdsaPublicKey extends Asn1OctetString implements PublicKeyContent {

    private ModifiableBigInteger xCoordinate;
    private ModifiableBigInteger yCoordinate;

    private ModifiableByteArray encodedPointBytes;

    public X509EcdhEcdsaPublicKey() {
        super("ecPublicKey");
    }

    public ModifiableBigInteger getxCoordinate() {
        return xCoordinate;
    }

    public void setxCoordinate(ModifiableBigInteger xCoordinate) {
        this.xCoordinate = xCoordinate;
    }

    public void setxCoordinate(BigInteger xCoordinate) {
        this.xCoordinate = ModifiableVariableFactory.safelySetValue(this.xCoordinate, xCoordinate);
    }

    public ModifiableBigInteger getyCoordinate() {
        return yCoordinate;
    }

    public void setyCoordinate(ModifiableBigInteger yCoordinate) {
        this.yCoordinate = yCoordinate;
    }

    public void setyCoordinate(BigInteger yCoordinate) {
        this.yCoordinate = ModifiableVariableFactory.safelySetValue(this.yCoordinate, yCoordinate);
    }

    public ModifiableByteArray getEncodedPointBytes() {
        return encodedPointBytes;
    }

    public void setEncodedPointBytes(ModifiableByteArray encodedPointBytes) {
        this.encodedPointBytes = encodedPointBytes;
    }

    public void setEncodedPointBytes(byte[] encodedPointBytes) {
        this.encodedPointBytes =
                ModifiableVariableFactory.safelySetValue(this.encodedPointBytes, encodedPointBytes);
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new X509EcdhEcdsaPublicKeyHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new X509EcdhEcdsaPublicKeyParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new X509EcdhEcdsaPublicKeyPreparator(chooser, this);
    }

    @Override
    public X509PublicKeyType getX509PublicKeyType() {
        return X509PublicKeyType.ECDH_ECDSA;
    }
}
