/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.X509Component;

/**
 * A parser for the X509 module that always parses the the structure of the asn1 field and then
 * passes the content of the field to the implementation
 */
public abstract class X509ComponentParser<Encodable extends X509Component>
        extends Asn1Parser<Encodable> implements X509Parser {

    protected final X509Chooser chooser;

    public X509ComponentParser(X509Chooser chooser, Encodable encodable) {
        super(encodable);
        this.chooser = chooser;
    }
}
