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
import de.rub.nds.x509attacker.x509.base.publickey.X509Ed25519PublicKey;

public class Ed25519PublicKeyPreparator
        extends X509PublicKeyContentPreparator<X509Ed25519PublicKey> {

    public Ed25519PublicKeyPreparator(X509Chooser chooser, X509Ed25519PublicKey instance) {
        super(chooser, instance);
    }

    @Override
    public void prepare() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
