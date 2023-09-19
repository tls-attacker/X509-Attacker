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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExplicitParser<InnerField extends X509Component> implements X509Parser {

    private static final Logger LOGGER = LogManager.getLogger();

    private X509Chooser chooser;
    private X509Explicit<InnerField> explicit;

    public ExplicitParser(X509Chooser chooser, X509Explicit<InnerField> explicit) {
        this.chooser = chooser;
        this.explicit = explicit;
    }

    @Override
    public void parse(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing X509Explicit");
        ParserHelper.parseStructure(explicit, inputStream);
        explicit.getInnerField()
                .getParser(chooser)
                .parse(
                        new BufferedInputStream(
                                new ByteArrayInputStream(explicit.getContent().getValue())));
        explicit.getInnerField().getHandler(chooser).adjustContextAfterParse();
    }
}
