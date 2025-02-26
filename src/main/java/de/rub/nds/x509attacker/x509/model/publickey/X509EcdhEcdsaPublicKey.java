/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model.publickey;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.crypto.ec.PointFormatter;
import de.rub.nds.protocol.crypto.key.EcdhPublicKey;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.math.BigInteger;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509EcdhEcdsaPublicKey implements PublicKeyContent {

    private ModifiableBigInteger xCoordinate;
    private ModifiableBigInteger yCoordinate;

    private ModifiableByteArray encodedPointBytes;

    public X509EcdhEcdsaPublicKey() {}

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
    public X509PublicKeyType getX509PublicKeyType() {
        return X509PublicKeyType.ECDH_ECDSA;
    }

    @Override
    public void prepare(X509Chooser chooser) {
        X509NamedCurve namedCurve = chooser.getConfig().getDefaultSubjectNamedCurve();
        Point publicKey =
                namedCurve
                        .getParameters()
                        .getGroup()
                        .nTimesGroupOperationOnGenerator(chooser.getConfig().getEcPrivateKey());
        this.setxCoordinate(publicKey.getFieldX().getData());
        this.setyCoordinate(publicKey.getFieldY().getData());
        EcdhPublicKey ecdhPublicKey =
                new EcdhPublicKey(
                        this.getxCoordinate().getValue(),
                        this.getyCoordinate().getValue(),
                        chooser.getConfig().getDefaultSubjectNamedCurve().getParameters());
        this.setEncodedPointBytes(
                PointFormatter.formatToByteArray(
                        chooser.getConfig().getDefaultSubjectNamedCurve().getParameters(),
                        ecdhPublicKey.getPublicPoint(),
                        chooser.getConfig().getDefaultEcPointFormat()));
    }

    @Override
    public byte[] getEncoded(X509Chooser chooser) {
        return this.getEncodedPointBytes().getValue();
    }

    @Override
    public void adjustInContext(X509Chooser chooser) {
        chooser.getContext()
                .setSubjectEcPublicKey(
                        PointFormatter.formatFromByteArray(
                                chooser.getSubjectNamedCurve().getParameters(),
                                getEncodedPointBytes().getValue()));
    }

    @Override
    public void readIn(X509Chooser chooser, byte[] bytesToRead) {
        this.setEncodedPointBytes(bytesToRead);
        Point publicKeyPoint =
                PointFormatter.formatFromByteArray(
                        chooser.getSubjectNamedCurve().getParameters(), bytesToRead);
        this.setxCoordinate(publicKeyPoint.getFieldX().getData());
        this.setyCoordinate(publicKeyPoint.getFieldY().getData());
    }
}
