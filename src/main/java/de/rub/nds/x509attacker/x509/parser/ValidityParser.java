/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.Validity;
import java.io.BufferedInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ValidityParser extends X509ComponentContainerParser<Validity> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ValidityParser(X509Chooser chooser, Validity validity) {
        super(chooser, validity);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing Validity");
        parseNotBefore(inputStream);
        parseNotAfter(inputStream);
    }

    private void parseNotBefore(BufferedInputStream inputStream) {
        encodable.getNotBefore().getParser(chooser).parse(inputStream);
        encodable.getNotBefore().getHandler(chooser).adjustContextAfterParse();
        LOGGER.debug(
                "Parsed NotBefore Date as: {}",
                encodable.getNotBefore().getTimeValue().toLocalDate());
    }

    private void parseNotAfter(BufferedInputStream inputStream) {
        encodable.getNotAfter().getParser(chooser).parse(inputStream);
        encodable.getNotAfter().getHandler(chooser).adjustContextAfterParse();
        LOGGER.debug(
                "Parsed NotAfter Date as: {}",
                encodable.getNotAfter().getTimeValue().toLocalDate());
    }
}
