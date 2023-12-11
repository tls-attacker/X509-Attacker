/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser.publickey.parameters;

import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509DssParameters;
import de.rub.nds.x509attacker.x509.parser.X509ComponentContainerParser;
import java.io.BufferedInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X509DssParametersParser extends X509ComponentContainerParser<X509DssParameters> {

    private static final Logger LOGGER = LogManager.getLogger();

    public X509DssParametersParser(X509Chooser chooser, X509DssParameters x509DssParameters) {
        super(chooser, x509DssParameters);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing DssParameters");
        parseP(inputStream);
        parseQ(inputStream);
        parseG(inputStream);
    }

    private void parseG(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1Integer(encodable.getG(), inputStream);
        LOGGER.debug("Parsing G: {}", encodable.getG().getValue().getValue());
    }

    private void parseQ(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1Integer(encodable.getQ(), inputStream);
        LOGGER.debug("Parsing Q: {}", encodable.getQ().getValue().getValue());
    }

    private void parseP(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1Integer(encodable.getP(), inputStream);
        LOGGER.debug("Parsing P: {}", encodable.getP().getValue().getValue());
    }
}
