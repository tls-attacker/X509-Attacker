/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import java.io.BufferedInputStream;

public class X509Asn1ObjectIdentifierParser extends Asn1Parser<Asn1ObjectIdentifier>
        implements X509Parser {

    protected final X509Chooser chooser;

    public X509Asn1ObjectIdentifierParser(X509Chooser chooser, Asn1ObjectIdentifier field) {
        super(field);
        this.chooser = chooser;
    }

    @Override
    public final void parse(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1ObjectIdentifier(encodable, inputStream);
    }
}
