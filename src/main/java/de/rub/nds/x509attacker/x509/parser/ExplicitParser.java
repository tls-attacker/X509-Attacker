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
import de.rub.nds.x509attacker.x509.model.X509Component;
import de.rub.nds.x509attacker.x509.model.X509Explicit;
import java.io.ByteArrayInputStream;
import java.io.InputStream;

public class ExplicitParser<InnerField extends X509Component> implements X509Parser {

    private X509Chooser chooser;
    private X509Explicit<InnerField> explicit;

    public ExplicitParser(X509Chooser chooser, X509Explicit<InnerField> explicit) {
        this.chooser = chooser;
        this.explicit = explicit;
    }

    @Override
    public void parse(InputStream inputStream) {
        ParserHelper.parseStructure(explicit, inputStream);
        explicit.getInnerField()
                .getParser(chooser)
                .parse(new ByteArrayInputStream(explicit.getContent().getValue()));
    }
}
