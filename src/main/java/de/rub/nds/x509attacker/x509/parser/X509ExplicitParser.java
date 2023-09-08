/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.X509Component;
import de.rub.nds.x509attacker.x509.model.X509Explicit;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;

public class X509ExplicitParser<InnerField extends X509Component>
        extends X509ComponentParser<X509Explicit<InnerField>> {

    public X509ExplicitParser(X509Chooser chooser, X509Explicit<InnerField> encodable) {
        super(chooser, encodable);
    }

    @Override
    public void parse(BufferedInputStream inputStream) {
        ParserHelper.parseStructure(encodable, inputStream);
        encodable
                .getInnerField()
                .getParser(chooser)
                .parse(
                        new BufferedInputStream(
                                new ByteArrayInputStream(encodable.getContent().getValue())));
    }
}
