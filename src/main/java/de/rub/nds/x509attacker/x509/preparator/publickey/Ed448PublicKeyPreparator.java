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
import de.rub.nds.x509attacker.x509.model.publickey.X509Ed448PublicKey;
import de.rub.nds.x509attacker.x509.preparator.X509Asn1FieldPreparator;

public class Ed448PublicKeyPreparator extends X509Asn1FieldPreparator<X509Ed448PublicKey> {

    public Ed448PublicKeyPreparator(X509Chooser chooser, X509Ed448PublicKey instance) {
        super(chooser, instance);
    }

    @Override
    protected byte[] encodeContent() {
        throw new UnsupportedOperationException("Unimplemented method 'encodeContent'");
    }
}
