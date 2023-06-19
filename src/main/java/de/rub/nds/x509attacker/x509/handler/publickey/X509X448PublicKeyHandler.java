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
import de.rub.nds.x509attacker.x509.handler.X509FieldHandler;
import de.rub.nds.x509attacker.x509.model.publickey.X509X448PublicKey;

public class X509X448PublicKeyHandler extends X509FieldHandler<X509X448PublicKey> {

    public X509X448PublicKeyHandler(X509Chooser chooser, X509X448PublicKey publicKey) {
        super(chooser, publicKey);
    }

    @Override
    public void adjustContext() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
