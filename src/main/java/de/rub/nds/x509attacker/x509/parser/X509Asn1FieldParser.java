/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.PushbackInputStream;

/**
 * A parser for the X509 module that always parses the the structure of the asn1 field and then
 * passes the content of the field to the implementation
 */
public abstract class X509Asn1FieldParser<Field extends Asn1Field> extends Asn1Parser<Field>
        implements X509Parser {

    protected final X509Chooser chooser;

    public X509Asn1FieldParser(X509Chooser chooser, Field field) {
        super(field);
        this.chooser = chooser;
    }

    @Override
    public final void parse(InputStream inputStream) {
        Asn1ParserHelper.parseStructure(encodable, inputStream);
        parseContent(
                new PushbackInputStream(
                        new ByteArrayInputStream(encodable.getContent().getValue())));
    }

    protected abstract void parseContent(PushbackInputStream inputStream);
}
