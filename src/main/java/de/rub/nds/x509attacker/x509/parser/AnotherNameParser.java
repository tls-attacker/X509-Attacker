/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.AnotherName;
import java.io.PushbackInputStream;

public class AnotherNameParser extends X509ComponentContainerParser<AnotherName> {

    public AnotherNameParser(X509Chooser chooser, AnotherName otherName) {
        super(chooser, otherName);
    }

    @Override
    protected void parseSubcomponents(PushbackInputStream inputStream) {
        ParserHelper.parseAsn1ObjectIdentifier(encodable.getTypeId(), inputStream);
        // TODO parse oid specific value
        throw new UnsupportedOperationException("Unimplemented method 'parseSubcomponents'");
    }
}
