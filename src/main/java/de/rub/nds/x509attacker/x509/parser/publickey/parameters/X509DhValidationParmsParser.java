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
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509DhValidationParms;
import de.rub.nds.x509attacker.x509.parser.X509ComponentContainerParser;
import java.io.BufferedInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X509DhValidationParmsParser
        extends X509ComponentContainerParser<X509DhValidationParms> {

    private Logger LOGGER = LogManager.getLogger();

    public X509DhValidationParmsParser(
            X509Chooser chooser, X509DhValidationParms x509DhValidationParms) {
        super(chooser, x509DhValidationParms);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing DhValidationParms");
        parseSeed(inputStream);
        parsePgenCounter(inputStream);
    }

    private void parsePgenCounter(BufferedInputStream inputStream) {
        LOGGER.debug("Parsed PgenCounter: {}", encodable.getPgenCounter().getValue().getValue());
        ParserHelper.parseAsn1Integer(encodable.getPgenCounter(), inputStream);
    }

    private void parseSeed(BufferedInputStream inputStream) {
        LOGGER.debug("Parsed Seed: {}", encodable.getSeed().getContent().getValue());
        ParserHelper.parseAsn1BitString(encodable.getSeed(), inputStream);
    }
}
