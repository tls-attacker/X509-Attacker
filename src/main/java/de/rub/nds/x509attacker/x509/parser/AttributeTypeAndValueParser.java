/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.asn1.model.Asn1UnknownField;
import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.protocol.exception.ParserException;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.DirectoryStringChoiceType;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.model.AttributeTypeAndValue;
import de.rub.nds.x509attacker.x509.model.DirectoryString;
import java.io.BufferedInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AttributeTypeAndValueParser
        extends X509ComponentContainerParser<AttributeTypeAndValue> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AttributeTypeAndValueParser(
            X509Chooser chooser, AttributeTypeAndValue attributeTypeAndValue) {
        super(chooser, attributeTypeAndValue);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        LOGGER.debug("Parsing AttributeTypeAndValue");
        parseType(inputStream);

        // Depending on the Type we can now parse the correct valueConfig
        X500AttributeType attributeType = getAttributeType();
        LOGGER.debug(
                "AttributeType: {} ({})",
                encodable.getType().getValue().getValue(),
                attributeType != null ? attributeType.name() : "unknown");
        if (attributeType == null) {
            LOGGER.debug("AttributeType is unknown. Parsing as unknown field.");
            Asn1UnknownField unknownField = ParserHelper.parseUnknown(inputStream);
            encodable.setValue(unknownField);
        } else {
            switch (attributeType) {
                case COMMON_NAME:
                case LOCALITY:
                case STATE_OR_PROVINCE_NAME:
                case ORGANISATION_NAME:
                case ORGANISATION_UNIT_NAME:
                case COUNTRY_NAME:
                    encodable.setAttributeTypeConfig(attributeType);
                    // I think this is wrong according to the RFC but is seen in the wild
                    parseDirectoryString(inputStream, attributeType);
                    break;

                default:
                    throw new ParserException(
                            String.format(
                                    "Did not anticipate X509AttributeType: %s",
                                    attributeType.toString()));
            }
        }
    }

    private void parseDirectoryString(
            BufferedInputStream inputStream, X500AttributeType attributeType) {
        LOGGER.debug("Parsing: {} as DirectoryString", attributeType.toString());
        DirectoryString directoryString = new DirectoryString("string");
        directoryString.getParser(chooser).parse(inputStream);
        directoryString.setDirectoryStringChoiceType(
                DirectoryStringChoiceType.fromChoice(directoryString.getSelectedChoice()));
        directoryString.getHandler(chooser).adjustContextAfterParse();
        encodable.setValue(directoryString);
    }

    private X500AttributeType getAttributeType() {
        X500AttributeType attributeType =
                X500AttributeType.decodeFromOidBytes(
                        encodable.getType().getValueAsOid().getEncoded());
        return attributeType;
    }

    private void parseType(BufferedInputStream inputStream) {
        ParserHelper.parseAsn1ObjectIdentifier(encodable.getType(), inputStream);
        LOGGER.debug("Parsed Type: {}", encodable.getType().getValue().getValue());
    }
}
