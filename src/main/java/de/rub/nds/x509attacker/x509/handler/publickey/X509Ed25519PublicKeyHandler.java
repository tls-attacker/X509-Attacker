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
import de.rub.nds.x509attacker.x509.model.publickey.X509Ed25519PublicKey;

public class X509Ed25519PublicKeyHandler extends X509FieldHandler<X509Ed25519PublicKey> {

    public X509Ed25519PublicKeyHandler(X509Chooser chooser, X509Ed25519PublicKey publicKey) {
        super(chooser, publicKey);
    }

    @Override
    public void adjustContextAfterParse() {
        adjustContext();
    }

    @Override
    public void adjustContextAfterPrepare() {
        adjustContext();
        context.setSubjectEd25519PrivateKey(config.getDefaultSubjectEd25519PrivateKey());
    }

    public void adjustContext() {
        context.setSubjectPublicKeyType(X509PublicKeyType.ED25519);
        context.setSubjectEd25519PublicKey(component.getContent().getValue());
    }
}
