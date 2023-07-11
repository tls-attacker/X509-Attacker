/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
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

public class ExtensionsParser extends X509ComponentContainerParser<Extensions> {

    public ExtensionsParser(X509Chooser chooser, Extensions extensions) {
        super(chooser, extensions);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        try {
            while (inputStream.available() > 0) {
                Extension element = new Extension("extension");
                element.getParser(chooser).parse(inputStream);
                element.getHandler(chooser).adjustContext();
                encodable.addExtension(element);
            }
        } catch (IOException E) {
            throw new ParserException("IOException in RelativeDistinguishedNameParser", E);
        }
    }
}
