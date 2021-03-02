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
 * PolicyQualifierInfo ::= SEQUENCE { policyQualifierId PolicyQualifierId, qualifier ANY DEFINED BY policyQualifierId }
 * }
 */
public class PolicyQualifierInfo extends X509Model<Asn1Sequence> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String type = "PolicyQualifierInfo";

    public Asn1ObjectIdentifier policyQualifierId; // PolicyQualifierId ::= OBJECT IDENTIFIER ( id-qt-cps |
                                                   // id-qt-unotice )
    public Asn1Encodable qualifier;

    public static PolicyQualifierInfo getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        return new PolicyQualifierInfo(intermediateAsn1Field, identifier);

    }

    private PolicyQualifierInfo(IntermediateAsn1Field intermediateAsn1Field, String identifier) {
        asn1 = (Asn1Sequence) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
            Asn1SequenceFT.class, identifier, type);

        // policyQualifierId
        policyQualifierId = (Asn1ObjectIdentifier) X509Translator.translateSingleIntermediateField(
            intermediateAsn1Field.getChildren().get(0), Asn1ObjectIdentifierFT.class, "policyQualifierId", "");
        asn1.addChild(policyQualifierId);

        // qualifier
        // TODO: Parameter vom Typ any hier mittels algemeinen Parser abgedeckt
        // --> kann erweitern werden Siehe RFC5280 - "4.2.1.4. Certificate Policies" (Qualifier ::= CHOICE {...})
        qualifier = (Asn1Encodable) X509Translator
            .translateSingleIntermediateField(intermediateAsn1Field.getChildren().get(1), "qualifier", "");
        asn1.addChild(qualifier);

        // LOGGER.warn("Testing required: Parsing of PolicyQualifierInfo->qualifier (ANY DEFINED BY
        // policyQualifierId)");

    }

}
