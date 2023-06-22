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
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509DssParameters;
import de.rub.nds.x509attacker.x509.parser.X509ComponentContainerParser;
import java.io.PushbackInputStream;

public class X509DssParametersParser extends X509ComponentContainerParser<X509DssParameters> {

    public X509DssParametersParser(X509Chooser chooser, X509DssParameters x509DssParameters) {
        super(chooser, x509DssParameters);
    }

    @Override
    protected void parseSubcomponents(PushbackInputStream inputStream) {
        ParserHelper.parseAsn1Integer(encodable.getP(), inputStream);
        ParserHelper.parseAsn1Integer(encodable.getQ(), inputStream);
        ParserHelper.parseAsn1Integer(encodable.getG(), inputStream);
    }
}
