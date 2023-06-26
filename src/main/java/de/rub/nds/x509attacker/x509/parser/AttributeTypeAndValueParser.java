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
import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.model.AttributeTypeAndValue;
import de.rub.nds.x509attacker.x509.model.DirectoryString;
import java.io.BufferedInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AttributeTypeAndValueParser
        extends X509ComponentContainerParser<AttributeTypeAndValue> {

    @SuppressWarnings("unused")
    private static final Logger LOGGER = LogManager.getLogger();

    public AttributeTypeAndValueParser(
            X509Chooser chooser, AttributeTypeAndValue attributeTypeAndValue) {
        super(chooser, attributeTypeAndValue);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1ObjectIdentifier(encodable.getType(), inputStream);
        // Depending on the Type we can now parse the correct valueConfig
        X500AttributeType attributeType =
                X500AttributeType.decodeFromOidBytes(
                        encodable.getType().getValueAsOid().getEncoded());
        if (attributeType == null) {
            throw new ParserException(
                    "Unknown attribute type: " + encodable.getType().getValue().getValue());
        }
        switch (attributeType) {
            case COMMON_NAME:
            case LOCALITY:
            case STATE_OR_PROVINCE_NAME:
            case ORGANISATION_NAME:
            case ORGANISATION_UNIT_NAME:
            case COUNTRY_NAME: // I think this is wrong according to the RFC but is seen in the wild
                DirectoryString directoryString = new DirectoryString("string");
                directoryString.getParser(chooser).parse(inputStream);
                encodable.setValue(directoryString);
                break;
            default:
                throw new ParserException(
                        "Did not anticipate X509AttributeType: " + attributeType.toString());
        }
    }
}
