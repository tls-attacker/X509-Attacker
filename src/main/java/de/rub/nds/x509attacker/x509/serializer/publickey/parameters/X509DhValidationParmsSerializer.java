/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.serializer.parameters;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509DhValidationParms;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;

public class X509DhValidationParmsSerializer implements X509Serializer {

    public X509DhValidationParmsSerializer(
            X509Chooser chooser, X509DhValidationParms x509DhValidationParms) {}

    @Override
    public byte[] serialize() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'serialize'");
    }
}
