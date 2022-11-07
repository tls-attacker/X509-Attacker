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
import de.rub.nds.asn1.model.Asn1PrimitiveIa5String;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1ObjectIdentifierFT;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1PrimitiveIa5StringFT;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1PrimitiveOctetStringFT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * GeneralName ::= CHOICE { otherName [0] OtherName, rfc822Name [1] IA5String, dNSName [2] IA5String, x400Address [3]
 * ORAddress, directoryName [4] Name, ediPartyName [5] EDIPartyName, uniformResourceIdentifier [6] IA5String, iPAddress
 * [7] OCTET STRING, registeredID [8] OBJECT IDENTIFIER }
 *
 */

public class GeneralName extends X509Model<Asn1Encodable> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String type = "GeneralName";

    public X509Model choice;

    public static GeneralName getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        return new GeneralName(intermediateAsn1Field, identifier);

    }

    private GeneralName(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        boolean warningNewType = false;
        // Choice
        switch (intermediateAsn1Field.getTagNumber()) {

            case 0: // otherName [0] OtherName
                choice = OtherName.getInstance(intermediateAsn1Field.getChildren().get(0), "otherName", true);
                asn1 = choice.asn1;
                warningNewType = true;
                break;

            case 1: // rfc822Name [1] IA5String
                asn1 = (Asn1PrimitiveIa5String) X509Translator.translateSingleIntermediateField(true,
                    intermediateAsn1Field, Asn1PrimitiveIa5StringFT.class, identifier, "rfc822Name");
                choice = new X509Model<Asn1PrimitiveIa5String>();
                choice.asn1 = asn1;
                break;

            case 2: // dNSName [2] IA5String
                asn1 = (Asn1PrimitiveIa5String) X509Translator.translateSingleIntermediateField(true,
                    intermediateAsn1Field, Asn1PrimitiveIa5StringFT.class, identifier, "dNSName");
                choice = new X509Model<Asn1PrimitiveIa5String>();
                choice.asn1 = asn1;
                break;

            case 3: // x400Address [3] ORAddress
                LOGGER.warn("Not Implemented: GeneralName -> Parsing Tag 3 'ORAddress'");
                break;

            case 4: // directoryName [4] Name
                choice = Name.getInstance(intermediateAsn1Field.getChildren().get(0), "directoryName", true);
                asn1 = choice.asn1;
                warningNewType = true;
                break;

            case 5: // ediPartyName [5] EDIPartyName
                choice = EDIPartyName.getInstance(intermediateAsn1Field.getChildren().get(0), "ediPartyName", true);
                asn1 = choice.asn1;
                warningNewType = true;
                break;

            case 6: // uniformResourceIdentifier [6] IA5String
                asn1 = (Asn1PrimitiveIa5String) X509Translator.translateSingleIntermediateField(true,
                    intermediateAsn1Field, Asn1PrimitiveIa5StringFT.class, identifier, "uniformResourceIdentifier");
                choice = new X509Model<Asn1PrimitiveIa5String>();
                choice.asn1 = asn1;
                break;

            case 7: // iPAddress [7] OCTET STRING
                asn1 = (Asn1PrimitiveOctetString) X509Translator.translateSingleIntermediateField(true,
                    intermediateAsn1Field, Asn1PrimitiveOctetStringFT.class, identifier, "iPAddress");
                choice = new X509Model<Asn1PrimitiveOctetString>();
                choice.asn1 = asn1;
                break;

            case 8: // registeredID [8] OBJECT IDENTIFIER
                asn1 = (Asn1ObjectIdentifier) X509Translator.translateSingleIntermediateField(true,
                    intermediateAsn1Field, Asn1ObjectIdentifierFT.class, identifier, "registeredID");
                choice = new X509Model<Asn1ObjectIdentifier>();
                choice.asn1 = asn1;
                break;

            default:
                LOGGER.warn("Parser Error: GeneralName -> Default Case triggerd; no Parser defined for Tag Number: "
                    + intermediateAsn1Field.getChildren().get(0).getTagNumber());
        }

        if (warningNewType == true) {
            // LOGGER.warn("Testing required: Parsing of yet untested type of GeneralName; with Tag: " +
            // intermediateAsn1Field.getTagNumber());
        }

    }

}
