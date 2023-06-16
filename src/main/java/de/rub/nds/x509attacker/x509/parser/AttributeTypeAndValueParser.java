/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import java.io.PushbackInputStream;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.asn1.constants.TagClass;
import de.rub.nds.asn1.constants.UniversalTagNumber;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.base.AttributeTypeAndValue;

public class AttributeTypeAndValueParser extends X509Asn1FieldParser<AttributeTypeAndValue> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final AttributeTypeAndValue attributeTypeAndValue;

    public AttributeTypeAndValueParser(
            X509Chooser chooser, AttributeTypeAndValue attributeTypeAndValue) {
        super(chooser, attributeTypeAndValue);
        this.attributeTypeAndValue = attributeTypeAndValue;
    }

    @Override
    public void parseContent(PushbackInputStream inputStream) {
        attributeTypeAndValue.setType(new Asn1ObjectIdentifier("type"));
        ParserHelper.parseAsn1ObjectIdentifier(attributeTypeAndValue.getType(), inputStream);
        // Depending on the Type we can now parse the correct valueConfig
        X500AttributeType attributeType = X500AttributeType
                .decodeFromOidBytes(attributeTypeAndValue.getType().getValueAsOid().getEncoded());
        if (attributeType == null) {
            LOGGER.warn("Unknown AttributeType: {}. Parsing as unknown.",
                    attributeTypeAndValue.getType().getValue().getValue());
            ParserHelper.parseUnknown(inputStream);
        } else {
            switch (attributeType) {
                // @formatter:off
                /** 
                 * X520name ::= CHOICE {
                 *     teletexString TeletexString (SIZE (1..ub-name)),
                 *     printableString PrintableString (SIZE (1..ub-name)),
                 *     universalString UniversalString (SIZE (1..ub-name)),
                 *     utf8String UTF8String (SIZE (1..ub-name)),
                 *     bmpString BMPString (SIZE (1..ub-name)) 
                 * }
                 * 
                 * The same format also applies to localityName, stateOrProvinceName, organizationName, OU
                 */
                // @formatter:on
                case COMMON_NAME:
                case LOCALITY:
                case STATE_OR_PROVINCE_NAME:
                case ORGANISATION_NAME:
                case ORGANISATION_UNIT_NAME:
                    UniversalTagNumber tagNumber = ParserHelper.canParse(inputStream, TagClass.UNIVERSAL,
                            UniversalTagNumber.T61STRING,
                            UniversalTagNumber.PRINTABLESTRING,
                            UniversalTagNumber.UNIVERSALSTRING, UniversalTagNumber.UTF8STRING,
                            UniversalTagNumber.BMPSTRING);
                    ParserHelper.parseTagNumberOrUnkownField(inputStream, TagClass.UNIVERSAL, tagNumber);
                    break;
                case COUNTRY_NAME:
                    tagNumber = ParserHelper.canParse(inputStream, TagClass.UNIVERSAL, UniversalTagNumber.PRINTABLESTRING);
                    ParserHelper.parseTagNumberOrUnkownField(inputStream, TagClass.UNIVERSAL, tagNumber);
                    break;
                default:
                    LOGGER.error("Did not anticipate X509AttributeType: {}", attributeType.toString());
            }
        }

    }
}
