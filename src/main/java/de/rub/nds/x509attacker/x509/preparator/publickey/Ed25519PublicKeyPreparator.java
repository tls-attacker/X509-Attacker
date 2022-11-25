/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.publickey;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.Ed25519PublicKey;
import de.rub.nds.x509attacker.x509.preparator.X509ComponentPreparator;

public class Ed25519PublicKeyPreparator extends X509ComponentPreparator<Ed25519PublicKey> {

    public Ed25519PublicKeyPreparator(Ed25519PublicKey instance, X509Chooser chooser) {
        super(instance, chooser);
    }

    @Override
    protected byte[] encodeContent() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
