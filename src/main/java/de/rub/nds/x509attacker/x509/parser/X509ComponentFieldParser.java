/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.X509Component;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;

/**
 * A parser for the X509 module that always parses the the structure of the asn1 field and then
 * passes the content of the field to the implementation
 */
public abstract class X509ComponentFieldParser<Encodable extends X509Component>
        extends X509ComponentParser<Encodable> {

    protected final Asn1Field field;

    public X509ComponentFieldParser(X509Chooser chooser, Encodable encodable) {
        super(chooser, encodable);
        if (!(encodable instanceof Asn1Field)) {
            throw new IllegalArgumentException("Encodable must be an Asn1Field.");
        }
        this.field = (Asn1Field) encodable;
    }

    @Override
    public final void parse(BufferedInputStream inputStream) {
        ParserHelper.parseStructure(field, inputStream);
        parseContent(
                new BufferedInputStream(new ByteArrayInputStream(field.getContent().getValue())));
    }

    protected abstract void parseContent(BufferedInputStream inputStream);
}
