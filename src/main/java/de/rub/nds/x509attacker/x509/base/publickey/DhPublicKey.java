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
import de.rub.nds.asn1.preparator.Preparator;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.publickey.DhPublicKeyHandler;
import de.rub.nds.x509attacker.x509.parser.DhPublicKeyParser;
import de.rub.nds.x509attacker.x509.preparator.publickey.DhPublicKeyPreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class DhPublicKey extends X509PublicKeyContent {

    private Asn1Integer<X509Chooser> publicKey;

    public DhPublicKey() {
        super("dhPublicKey");
        publicKey = new Asn1Integer<>("publicKey");
    }

    public Asn1Integer<X509Chooser> getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(Asn1Integer<X509Chooser> publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public Preparator getPreparator(X509Chooser chooser) {
        return new DhPublicKeyPreparator(chooser, this);
    }

    @Override
    public Asn1FieldSerializer getSerializer() {
        return publicKey.getSerializer();
    }

    @Override
    public Asn1Parser<?, ?> getParser(X509Chooser chooser) {
        return new DhPublicKeyParser(chooser, this);
    }

    @Override
    public boolean isEllipticCurve() {
        return false;
    }

    @Override
    public boolean isCompatible(Integer tagNumber, Boolean constructed, Integer classType) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from
        // nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public Handler getHandler(X509Chooser chooser) {
        return new DhPublicKeyHandler(chooser, this);
    }
}
