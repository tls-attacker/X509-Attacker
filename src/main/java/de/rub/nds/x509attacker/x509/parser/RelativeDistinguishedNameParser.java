/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.AttributeTypeAndValue;
import de.rub.nds.x509attacker.x509.model.RelativeDistinguishedName;
import java.io.BufferedInputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RelativeDistinguishedNameParser
        extends X509ComponentContainerParser<RelativeDistinguishedName> {

    private static final Logger LOGGER = LogManager.getLogger();

    public RelativeDistinguishedNameParser(
            X509Chooser chooser, RelativeDistinguishedName relativeDistinguishedName) {
        super(chooser, relativeDistinguishedName);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing RelativeDistinguishedName");
        try {
            while (inputStream.available() > 0) {
                LOGGER.debug("Parsing AttributeTypeAndValue");
                AttributeTypeAndValue attributeTypeAndValue =
                        new AttributeTypeAndValue("attributeTypeAndValue");
                attributeTypeAndValue.getParser(chooser).parse(inputStream);
                attributeTypeAndValue.getHandler(chooser).adjustContextAfterParse();
                encodable.addAttributeTypeAndValue(attributeTypeAndValue);
            }
        } catch (IOException E) {
            throw new ParserException("IOException in RelativeDistinguishedNameParser", E);
        }
    }
}
