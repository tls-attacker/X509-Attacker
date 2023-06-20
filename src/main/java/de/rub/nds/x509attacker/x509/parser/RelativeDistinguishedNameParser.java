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
import de.rub.nds.x509attacker.x509.model.AttributeTypeAndValue;
import de.rub.nds.x509attacker.x509.model.RelativeDistinguishedName;
import java.io.IOException;
import java.io.PushbackInputStream;

public class RelativeDistinguishedNameParser
        extends X509ComponentContainerParser<RelativeDistinguishedName> {

    public RelativeDistinguishedNameParser(
            X509Chooser chooser, RelativeDistinguishedName relativeDistinguishedName) {
        super(chooser, relativeDistinguishedName);
    }

    @Override
    protected void parseSubcomponents(PushbackInputStream inputStream) {
        try {
            while (inputStream.available() > 0) {
                AttributeTypeAndValue element = new AttributeTypeAndValue("attributeTypeAndValue");
                element.getParser(chooser).parse(inputStream);
                encodable.addChild(element);
            }
        } catch (IOException E) {
            throw new ParserException("IOException in RelativeDistinguishedNameParser", E);
        }
    }
}
