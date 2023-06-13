/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.handler.publickey;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.X509DsaPublicKey;
import de.rub.nds.x509attacker.x509.handler.X509Handler;

public class X509DsaPublicKeyHandler extends X509Handler {

    private final X509DsaPublicKey publicKey;

    public X509DsaPublicKeyHandler(X509Chooser chooser, X509DsaPublicKey publicKey) {
        super(chooser);
        this.publicKey = publicKey;
    }

    @Override
    public void adjustContext() {
        context.setSubjectDsaPublicKeyY(publicKey.getValue().getValue());
        context.setSubjectDsaPrivateKey(config.getDsaPrivateKey());
    }
}
