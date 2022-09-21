/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
 * AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY DEFINED BY algorithm OPTIONAL }
 */
public class AlgorithmIdentifier extends X509Model<Asn1Sequence> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String type = "AlgorithmIdentifier";

    public Asn1ObjectIdentifier algorithm;
    public Asn1Encodable parameters;

    public static AlgorithmIdentifier getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        return new AlgorithmIdentifier(intermediateAsn1Field, identifier);

    }

    private AlgorithmIdentifier(IntermediateAsn1Field intermediateAsn1Field, String identifier) {
        asn1 = (Asn1Sequence) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
            Asn1SequenceFT.class, identifier, type);

        // algorithm
        algorithm = (Asn1ObjectIdentifier) X509Translator.translateSingleIntermediateField(
            intermediateAsn1Field.getChildren().get(0), Asn1ObjectIdentifierFT.class, "algorithm", "");
        asn1.addChild(algorithm);

        // parameters - can be optional
        if (intermediateAsn1Field.getChildren().size() == 2) {
            // TODO: Parameter vom Typ any hier mittels algemeinen Parser abgedeckt
            parameters = (Asn1Encodable) X509Translator
                .translateSingleIntermediateField(intermediateAsn1Field.getChildren().get(1), "parameters", "");
            asn1.addChild(parameters);
            // LOGGER.warn("Testing required: Parsing of AlgorithmIdentifier->parameters (ANY DEFINED BY algorithm)");
        }

    }

}
