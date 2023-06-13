/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.parser.Asn1FieldParser;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import java.io.InputStream;

public class X509Asn1IntegerParser extends Asn1FieldParser<Asn1Integer> implements X509Parser {

    protected final X509Chooser chooser;

    public X509Asn1IntegerParser(Asn1Integer field, X509Chooser chooser) {
        super(field);
        this.chooser = chooser;
    }

    @Override
    public final void parse(InputStream inputStream) {
        parseAsn1Integer(encodable, inputStream);
    }
}
