/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.publickey;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.X509RsaPublicKey;

public class X509RsaPublicKeyPreparator extends X509PublicKeyContentPreparator<X509RsaPublicKey> {

    public X509RsaPublicKeyPreparator(X509Chooser chooser, X509RsaPublicKey instance) {
        super(chooser, instance);
    }

    @Override
    public void prepare() {
        field.getRsaPublicKeyContentSequence()
                .getModulus()
                .setValue(chooser.getConfig().getRsaModulus());
        field.getRsaPublicKeyContentSequence()
                .getPublicExponent()
                .setValue(chooser.getConfig().getRsaPublicExponent());
        field.getRsaPublicKeyContentSequence().getPreparator(chooser).prepare();
    }
}
