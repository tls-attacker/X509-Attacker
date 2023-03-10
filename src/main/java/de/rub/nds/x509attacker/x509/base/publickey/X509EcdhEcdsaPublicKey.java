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
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.publickey.X509EcdhEcdsaPublicKeyHandler;
import de.rub.nds.x509attacker.x509.parser.X509EcdhEcdsaPublicKeyParser;
import de.rub.nds.x509attacker.x509.preparator.publickey.X509EcdhEcdsaPublicKeyPreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.math.BigInteger;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509EcdhEcdsaPublicKey extends PublicKeyContent {

    private ModifiableBigInteger xCoordinate;
    private ModifiableBigInteger yCoordinate;

    private ModifiableByte formatByte;

    private ModifiableByteArray pointOctets;

    public X509EcdhEcdsaPublicKey() {
        super("ecPublicKey");
    }

    @Override
    public X509EcdhEcdsaPublicKeyPreparator getPreparator(X509Chooser chooser) {
        return new X509EcdhEcdsaPublicKeyPreparator(chooser, this);
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

    public ModifiableByte getFormatByte() {
        return formatByte;
    }

    public void setFormatByte(ModifiableByte formatByte) {
        this.formatByte = formatByte;
    }

    public void setFormatByte(Byte formatByte) {
        this.formatByte = ModifiableVariableFactory.safelySetValue(this.formatByte, formatByte);
    }

    public ModifiableByteArray getPointOctets() {
        return pointOctets;
    }

    public void setPointOctets(ModifiableByteArray pointOctets) {
        this.pointOctets = pointOctets;
    }

    public void setPointOctets(byte[] pointOctets) {
        this.pointOctets = ModifiableVariableFactory.safelySetValue(this.pointOctets, pointOctets);
    }

    @Override
    public boolean isEllipticCurve() {
        return true;
    }

    @Override
    public X509EcdhEcdsaPublicKeyParser getParser(X509Chooser chooser) {
        return new X509EcdhEcdsaPublicKeyParser(chooser, this);
    }

    @Override
    public boolean isCompatible(Integer tagNumber, Boolean constructed, Integer classType) {
        return true;
    }

    @Override
    public Handler<X509Chooser> getHandler(X509Chooser chooser) {
        return new X509EcdhEcdsaPublicKeyHandler(chooser, this);
    }

    @Override
    public Asn1FieldSerializer getSerializer() {
        return null;
    }
}
