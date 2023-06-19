/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.X509DhPublicKey;
import java.io.PushbackInputStream;

public class X509DhPublicKeyParser extends X509Asn1FieldParser<X509DhPublicKey> {

    public X509DhPublicKeyParser(X509Chooser chooser, X509DhPublicKey dhPublicKey) {
        super(chooser, dhPublicKey);
    }

    @Override
    protected void parseContent(PushbackInputStream inputStream) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'parseContent'");
    }
}
