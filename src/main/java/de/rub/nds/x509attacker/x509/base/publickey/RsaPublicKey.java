/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base.publickey;

import de.rub.nds.asn1.preparator.Preparator;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.parser.RsaPublicKeyParser;
import de.rub.nds.x509attacker.x509.preparator.publickey.RsaPublicKeyPreparator;

public class RsaPublicKey extends X509PublicKeyContent {

    private RsaPublicKeyContentSequence rsaPublicKeyContentSequence;

    public RsaPublicKey() {
        super("rsaPublicKey");
        rsaPublicKeyContentSequence = new RsaPublicKeyContentSequence("rsaPublicKeyContent");
    }

    public RsaPublicKeyContentSequence getRsaPublicKeyContentSequence() {
        return rsaPublicKeyContentSequence;
    }

    public void setRsaPublicKeyContentSequence(
            RsaPublicKeyContentSequence rsaPublicKeyContentSequence) {
        this.rsaPublicKeyContentSequence = rsaPublicKeyContentSequence;
    }

    @Override
    public Asn1FieldSerializer getSerializer() {
        return rsaPublicKeyContentSequence.getSerializer();
    }

    @Override
    public Preparator getPreparator(X509Chooser chooser) {
        return new RsaPublicKeyPreparator(chooser, this);
    }

    @Override
    public void adjustKeyAsIssuer(X509Context context, X509CertificateConfig config) {
        context.setIssuerPublicKeyType(X509PublicKeyType.RSA);
        context.setIssuerRsaModulus(rsaPublicKeyContentSequence.getModulus().getValue().getValue());
        context.setIssuerRsaPrivateKey(config.getRsaPrivateKey());
    }

    @Override
    public boolean isEllipticCurve() {
        return false;
    }

    @Override
    public RsaPublicKeyParser getParser(X509Chooser chooser) {
        return new RsaPublicKeyParser(chooser, this);
    }

    @Override
    public boolean isCompatible(Integer tagNumber, Boolean constructed, Integer classType) {
        return rsaPublicKeyContentSequence.isCompatible(tagNumber, constructed, classType);
    }
}
