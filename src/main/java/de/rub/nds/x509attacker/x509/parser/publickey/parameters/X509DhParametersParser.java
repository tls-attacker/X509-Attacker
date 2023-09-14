/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser.publickey.parameters;

import de.rub.nds.asn1.constants.TagClass;
import de.rub.nds.asn1.constants.UniversalTagNumber;
import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509DhParameters;
import de.rub.nds.x509attacker.x509.parser.X509ComponentContainerParser;
import java.io.BufferedInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X509DhParametersParser extends X509ComponentContainerParser<X509DhParameters> {

    private static final Logger LOGGER = LogManager.getLogger();

    public X509DhParametersParser(X509Chooser chooser, X509DhParameters x509DhParameters) {
        super(chooser, x509DhParameters);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing DhParameters");
        parseP(inputStream);
        parseG(inputStream);

        // The Q value is NOT optional, but is not always present in the certificates
        // OpenSSL implements it as P and G always present, Q NEVER present and J sometimes present
        // which effectivly makes this not parseable. One can sort of solve this by testing the
        // parsed value
        // if the parsed value divides p-1. If it does, then it is q - if it does not, then it is j.
        // This is not a perfect solution, but it is the best we could do.
        if (hasQParameter(inputStream)) {
            parseQ(inputStream);
        }
        if (hasJParameter(inputStream)) {
            parseJ(inputStream);
        }
        if (hasValidationParams(inputStream)) {
            parseValidationParams(inputStream);
        }
    }

    private boolean hasValidationParams(BufferedInputStream inputStream) {
        return ParserHelper.canParse(
                inputStream, TagClass.UNIVERSAL, UniversalTagNumber.SEQUENCE.getIntValue());
    }

    private boolean hasQParameter(BufferedInputStream inputStream) {
        return ParserHelper.canParse(
                inputStream, TagClass.UNIVERSAL, UniversalTagNumber.INTEGER.getIntValue());
    }

    private boolean hasJParameter(BufferedInputStream inputStream) {
        return ParserHelper.canParse(
                inputStream, TagClass.UNIVERSAL, UniversalTagNumber.INTEGER.getIntValue());
    }

    private void parseValidationParams(BufferedInputStream inputStream) {
        encodable.getValidationParms().getParser(chooser).parse(inputStream);
    }

    private void parseJ(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1Integer(encodable.getJ(), inputStream);
        LOGGER.debug("Parsed J: {}", encodable.getJ().getValue().getValue());
    }

    private void parseQ(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1Integer(encodable.getQ(), inputStream);
        LOGGER.debug("Parsed Q: {}", encodable.getP().getValue().getValue());
    }

    private void parseG(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1Integer(encodable.getG(), inputStream);
        LOGGER.debug("Parsed G (generator): {}", encodable.getP().getValue().getValue());
    }

    private void parseP(BufferedInputStream inputStream) {
        parseJ(inputStream);
        LOGGER.debug("Parsed P (modulus): {}", encodable.getP().getValue().getValue());
    }
}
