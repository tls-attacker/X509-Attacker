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
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.x509.base.publickey.RsaPublicKey;
import de.rub.nds.x509attacker.x509.handler.X509Handler;

public class RsaPublicKeyHandler extends X509Handler {

    private final RsaPublicKey publicKey;

    public RsaPublicKeyHandler(X509Chooser chooser, RsaPublicKey publicKey) {
        super(chooser);
        this.publicKey = publicKey;
    }

    @Override
    public void adjustContext() {
        context.setIssuerPublicKeyType(X509PublicKeyType.RSA);
        context.setIssuerRsaModulus(
                publicKey.getRsaPublicKeyContentSequence().getModulus().getValue().getValue());
        context.setIssuerRsaPrivateKey(config.getRsaPrivateKey());
    }
}
