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
 * OtherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY DEFINED BY type-id } }
 */
public class OtherName extends X509Model<Asn1Sequence> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String type = "OtherName";

    public Asn1ObjectIdentifier type_id;
    public Asn1Encodable value;

    public static OtherName getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier,
        Boolean implicit) {

        return new OtherName(intermediateAsn1Field, identifier, implicit);

    }

    private OtherName(IntermediateAsn1Field intermediateAsn1Field, String identifier, Boolean implicit) {
        asn1 = (Asn1Sequence) X509Translator.translateSingleIntermediateField(true, intermediateAsn1Field,
            Asn1SequenceFT.class, identifier, type);

        // type-id
        type_id = (Asn1ObjectIdentifier) X509Translator.translateSingleIntermediateField(
            intermediateAsn1Field.getChildren().get(0), Asn1ObjectIdentifierFT.class, "type-id", "");
        asn1.addChild(type_id);

        // value
        // TODO: Cover parameter of Type any here with a general parser
        value = (Asn1Encodable) X509Translator
            .translateSingleIntermediateField(intermediateAsn1Field.getChildren().get(1), "value", "");
        asn1.addChild(value);

        // LOGGER.warn("Testing required: Parsing of OtherName->value (EXPLICIT ANY DEFINED BY type-id)");

    }

}
