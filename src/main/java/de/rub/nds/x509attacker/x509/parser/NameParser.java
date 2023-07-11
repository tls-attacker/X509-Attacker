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
import de.rub.nds.x509attacker.x509.model.Name;
import de.rub.nds.x509attacker.x509.model.RelativeDistinguishedName;
import java.io.BufferedInputStream;
import java.io.IOException;

public class NameParser extends X509ComponentContainerParser<Name> {

    public NameParser(X509Chooser chooser, Name name) {
        super(chooser, name);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        try {
            while (inputStream.available() > 0) {
                RelativeDistinguishedName rdn = new RelativeDistinguishedName("rdn");
                X509Parser rdnParser = rdn.getParser(chooser);
                rdnParser.parse(inputStream);
                encodable.addRelativeDistinguishedNames(rdn);
            }

        } catch (IOException e) {
            throw new ParserException("IOException during parsing Name: " + e.getMessage(), e);
        }
    }
}
