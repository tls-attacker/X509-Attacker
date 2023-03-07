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
import de.rub.nds.x509attacker.x509.base.publickey.X509DhPublicKey;
import de.rub.nds.x509attacker.x509.handler.X509Handler;

public class X509DhPublicKeyHandler extends X509Handler {

    private final X509DhPublicKey publicKey;

    public X509DhPublicKeyHandler(X509Chooser chooser, X509DhPublicKey publicKey) {
        super(chooser);
        this.publicKey = publicKey;
    }

    @Override
    public void adjustContext() {
        context.setSubjectDhPublicKey(publicKey.getPublicKey().getValue().getValue());
    }
}
