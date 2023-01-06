/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base.publickey;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.preparator.publickey.DsaPublicKeyPreparator;
import java.math.BigInteger;

public class DsaPublicKey extends X509PublicKeyContent {

    private Asn1Integer<X509Chooser> publicKeyY;

    public DsaPublicKey() {
        super("dsaPublicKey");
        publicKeyY = new Asn1Integer<>("y");
    }

    @Override
    public Asn1FieldSerializer getSerializer() {
        return publicKeyY.getSerializer();
    }

    @Override
    public DsaPublicKeyPreparator getPreparator(X509Chooser chooser) {
        return new DsaPublicKeyPreparator(this, chooser);
    }

    @Override
    public void adjustKeyAsIssuer(X509Context context, X509CertificateConfig config) {
        context.setIssuerDsaPublicKeyY(publicKeyY.getValue().getValue());
        context.setIssuerDsaPrivateKey(config.getDsaPrivateKey());
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
}
