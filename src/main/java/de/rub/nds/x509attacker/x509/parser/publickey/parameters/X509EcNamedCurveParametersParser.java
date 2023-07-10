/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser.publickey.parameters;

import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509EcNamedCurveParameters;
import de.rub.nds.x509attacker.x509.parser.X509ComponentParser;
import java.io.BufferedInputStream;

public class X509EcNamedCurveParametersParser
        extends X509ComponentParser<X509EcNamedCurveParameters> {

    public X509EcNamedCurveParametersParser(
            X509Chooser chooser, X509EcNamedCurveParameters x509EcNamedCurveParameters) {
        super(chooser, x509EcNamedCurveParameters);
    }

    @Override
    public void parse(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1ObjectIdentifier(encodable, inputStream);
    }
}
