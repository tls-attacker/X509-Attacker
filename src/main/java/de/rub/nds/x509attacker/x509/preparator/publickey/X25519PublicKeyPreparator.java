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
import de.rub.nds.x509attacker.x509.base.publickey.X509X25519PublicKey;

public class X25519PublicKeyPreparator extends X509PublicKeyContentPreparator<X509X25519PublicKey> {

    public X25519PublicKeyPreparator(X509Chooser chooser, X509X25519PublicKey instance) {
        super(chooser, instance);
    }

    @Override
    protected byte[] encodeContent() {
        throw new UnsupportedOperationException("Unimplemented method 'encodeContent'");
    }
}
