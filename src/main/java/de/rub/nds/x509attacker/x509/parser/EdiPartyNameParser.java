/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.constants.TagClass;
import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.EdiPartyName;
import java.io.BufferedInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EdiPartyNameParser extends X509ComponentContainerParser<EdiPartyName> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final int EXPLICIT_TAG_NUMBER = 0;

    public EdiPartyNameParser(X509Chooser chooser, EdiPartyName ediPartyName) {
        super(chooser, ediPartyName);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        if (ParserHelper.canParse(inputStream, TagClass.CONTEXT_SPECIFIC, EXPLICIT_TAG_NUMBER)) {
            LOGGER.debug("Trying to parse optional NameAssigner");
            encodable.getNameAssigner().getParser(chooser).parse(inputStream);
            encodable.getNameAssigner().getHandler(chooser).adjustContextAfterParse();
        }
        encodable.getPartyName().getParser(chooser).parse(inputStream);
        encodable.getPartyName().getHandler(chooser).adjustContextAfterParse();
        LOGGER.debug(
                "Parsed PartyName: {}",
                encodable
                        .getPartyName()
                        .getInnerField()
                        .getPrintableString()
                        .getValue()
                        .getValue());
    }
}
