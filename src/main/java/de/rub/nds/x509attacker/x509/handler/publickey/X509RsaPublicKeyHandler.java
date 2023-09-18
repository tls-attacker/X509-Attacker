/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.handler.publickey;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.x509.handler.X509FieldHandler;
import de.rub.nds.x509attacker.x509.model.publickey.X509RsaPublicKey;

public class X509RsaPublicKeyHandler extends X509FieldHandler<X509RsaPublicKey> {

    public X509RsaPublicKeyHandler(X509Chooser chooser, X509RsaPublicKey publicKey) {
        super(chooser, publicKey);
    }

    @Override
    public void adjustContextAfterParse() {
        adjustContext();
    }

    @Override
    public void adjustContextAfterPrepare() {
        adjustContext();
        context.setSubjectRsaPrivateKey(config.getRsaPrivateKey());
    }

    public void adjustContext() {
        context.setSubjectPublicKeyType(X509PublicKeyType.RSA);
        context.setSubjectRsaModulus(component.getModulus().getValue().getValue());
    }
}
