/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser.publickey.parameters;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509DhParameters;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import java.io.InputStream;

public class X509DhParametersParser implements X509Parser {

    public X509DhParametersParser(X509Chooser chooser, X509DhParameters x509DhParameters) {}

    @Override
    public void parse(InputStream inputStream) {
        throw new UnsupportedOperationException("Unimplemented method 'parse'");
    }
}
