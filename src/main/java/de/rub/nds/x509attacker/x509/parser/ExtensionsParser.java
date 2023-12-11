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
import de.rub.nds.x509attacker.x509.model.Extension;
import de.rub.nds.x509attacker.x509.model.Extensions;
import java.io.BufferedInputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExtensionsParser extends X509ComponentContainerParser<Extensions> {

    private Logger LOGGER = LogManager.getLogger();

    public ExtensionsParser(X509Chooser chooser, Extensions extensions) {
        super(chooser, extensions);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing Extensions");
        try {
            while (inputStream.available() > 0) {
                LOGGER.debug("Parsing Extension");
                Extension element = new Extension("extension");
                element.getParser(chooser).parse(inputStream);
                element.getHandler(chooser).adjustContextAfterParse();
                encodable.addExtension(element);
            }
        } catch (IOException E) {
            throw new ParserException("IOException in RelativeDistinguishedNameParser", E);
        }
    }
}
