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
import de.rub.nds.x509attacker.x509.base.publickey.RsaPublicKey;

public class RsaPublicKeyPreparator extends X509PublicKeyContentPreparator<RsaPublicKey> {

    public RsaPublicKeyPreparator(X509Chooser chooser, RsaPublicKey instance) {
        super(chooser, instance);
    }

    @Override
    public void prepare() {
        field.getRsaPublicKeyContentSequence()
                .getModulus()
                .setValue(chooser.getConfig().getRsaModulus());
        field.getRsaPublicKeyContentSequence()
                .getPublicExponent()
                .setValue(chooser.getConfig().getRsaPublicKey());
        field.getRsaPublicKeyContentSequence().getPreparator(chooser).prepare();
    }
}
