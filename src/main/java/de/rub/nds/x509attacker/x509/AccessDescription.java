/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509;

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
 * AccessDescription ::= SEQUENCE { accessMethod OBJECT IDENTIFIER, accessLocation GeneralName }
 */
public class AccessDescription extends X509Model<Asn1Sequence> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String type = "AcessDescription";

    public Asn1ObjectIdentifier accessMethod;
    public GeneralName accessLocation;

    public static AccessDescription getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        return new AccessDescription(intermediateAsn1Field, identifier);

    }

    private AccessDescription(IntermediateAsn1Field intermediateAsn1Field, String identifier) {
        asn1 = (Asn1Sequence) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
            Asn1SequenceFT.class, identifier, type);

        // algorithm
        accessMethod = (Asn1ObjectIdentifier) X509Translator.translateSingleIntermediateField(
            intermediateAsn1Field.getChildren().get(0), Asn1ObjectIdentifierFT.class, "accessMethod", "");
        asn1.addChild(accessMethod);

        accessLocation = GeneralName.getInstance(intermediateAsn1Field.getChildren().get(1), "accessLocation");
        asn1.addChild(accessLocation.asn1);

    }

}
