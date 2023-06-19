/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.serializer.publickey.parameters;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509EcNamedCurveParameters;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;

public class X509EcNamedCurveParametersSerializer implements X509Serializer {

    public X509EcNamedCurveParametersSerializer(
            X509Chooser chooser, X509EcNamedCurveParameters x509DssParameters) {}

    @Override
    public byte[] serialize() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'serialize'");
    }
}
