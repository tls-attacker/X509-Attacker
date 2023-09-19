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
import de.rub.nds.x509attacker.x509.model.Name;
import de.rub.nds.x509attacker.x509.model.RelativeDistinguishedName;
import java.io.BufferedInputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NameParser extends X509ComponentContainerParser<Name> {

    private final Logger LOGGER = LogManager.getLogger();

    public NameParser(X509Chooser chooser, Name name) {
        super(chooser, name);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing Name");
        try {
            while (inputStream.available() > 0) {
                LOGGER.debug("Parsing RelativeDistinguisedName");
                RelativeDistinguishedName relativeDistinguishedName =
                        new RelativeDistinguishedName("rdn");
                relativeDistinguishedName.getParser(chooser).parse(inputStream);
                relativeDistinguishedName.getHandler(chooser).adjustContextAfterParse();
                encodable.addRelativeDistinguishedNames(relativeDistinguishedName);
            }

        } catch (IOException e) {
            throw new ParserException("IOException during parsing Name: " + e.getMessage(), e);
        }
    }
}
