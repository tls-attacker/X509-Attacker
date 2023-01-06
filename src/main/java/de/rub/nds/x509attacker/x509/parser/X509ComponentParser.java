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
import de.rub.nds.asn1.parser.Asn1FieldParser;
import de.rub.nds.x509attacker.chooser.X509Chooser;

public abstract class X509ComponentParser<Field extends Asn1Field<X509Chooser>>
        extends Asn1FieldParser<X509Chooser, Field> {

    public X509ComponentParser(X509Chooser chooser, Field field) {
        super(chooser, field);
    }
}
