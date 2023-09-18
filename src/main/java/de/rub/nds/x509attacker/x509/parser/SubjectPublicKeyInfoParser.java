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
import de.rub.nds.x509attacker.x509.model.SubjectPublicKeyInfo;
import java.io.BufferedInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SubjectPublicKeyInfoParser extends X509ComponentContainerParser<SubjectPublicKeyInfo> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SubjectPublicKeyInfoParser(X509Chooser chooser, SubjectPublicKeyInfo field) {
        super(chooser, field);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing SubjectPublicKeyInfo");
        encodable.getAlgorithm().getParser(chooser).parse(inputStream);
        LOGGER.debug(
                "Parsed Algorithm: {}",
                encodable.getAlgorithm().getAlgorithm().getValue().getValue());
        encodable.getAlgorithm().getHandler(chooser).adjustContextAfterParse();
        encodable.getSubjectPublicKeyBitString().getParser(chooser).parse(inputStream);
        LOGGER.debug(
                "Parsed Algorithm: {}",
                encodable.getAlgorithm().getAlgorithm().getValue().getValue());
    }
}
