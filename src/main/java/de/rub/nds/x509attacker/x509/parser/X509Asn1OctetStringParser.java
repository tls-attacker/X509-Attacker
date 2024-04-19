/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.model.Asn1OctetString;
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import java.io.BufferedInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X509Asn1OctetStringParser extends Asn1Parser<Asn1OctetString> implements X509Parser {

    private static final Logger LOGGER = LogManager.getLogger();

    protected final X509Chooser chooser;

    public X509Asn1OctetStringParser(X509Chooser chooser, Asn1OctetString field) {
        super(field);
        this.chooser = chooser;
    }

    @Override
    public final void parse(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing X509Asn1OctetString ({})", encodable.getIdentifier());
        ParserHelper.parseAsn1OctetString(encodable, inputStream);
        LOGGER.debug(
                "Parsed X509Asn1OctetString ({}): {}",
                encodable.getIdentifier(),
                encodable.getValue().getValue());
    }
}