/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1ObjectIdentifierFT;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1SequenceFT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * AttributeTypeAndValue ::= SEQUENCE { type AttributeType, value AttributeValue }
 * 
 * AttributeType ::= OBJECT IDENTIFIER
 * 
 * AttributeValue ::= ANY -- DEFINED BY AttributeType
 * 
 * DirectoryString ::= CHOICE { teletexString TeletexString (SIZE (1..MAX)), printableString PrintableString (SIZE
 * (1..MAX)), universalString UniversalString (SIZE (1..MAX)), utf8String UTF8String (SIZE (1..MAX)), bmpString
 * BMPString (SIZE (1..MAX)) }
 * 
 * 
 */
public class AttributeTypeAndValue extends X509Model<Asn1Sequence> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String _type = "AttributeTypeAndValue";

    public Asn1ObjectIdentifier type;
    public Asn1Encodable value;

    public static AttributeTypeAndValue getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        return new AttributeTypeAndValue(intermediateAsn1Field, identifier);

    }

    private AttributeTypeAndValue(IntermediateAsn1Field intermediateAsn1Field, String identifier) {
        asn1 = (Asn1Sequence) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
            Asn1SequenceFT.class, identifier, _type);

        // type
        type = (Asn1ObjectIdentifier) X509Translator.translateSingleIntermediateField(
            intermediateAsn1Field.getChildren().get(0), Asn1ObjectIdentifierFT.class, "type", "AttributeType");
        asn1.addChild(type);

        // value
        // TODO: depend on the ObjectIdentifier
        value = DirectoryString.getInstance(intermediateAsn1Field.getChildren().get(1), "value").asn1;
        asn1.addChild(value);

        // LOGGER.warn("Testing required: Parsing of AttributeTypeAndValue->value (EXPLICIT ANY DEFINED BY type)");
    }

}
