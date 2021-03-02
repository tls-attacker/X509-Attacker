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
import de.rub.nds.asn1.model.Asn1PrimitiveIa5String;
import de.rub.nds.asn1.model.Asn1PrimitivePrintableString;
import de.rub.nds.asn1.model.Asn1PrimitiveT61String;
import de.rub.nds.asn1.model.Asn1PrimitiveUtf8String;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1PrimitiveIa5StringFT;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1PrimitivePrintableStringFT;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1PrimitiveT61StringFT;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1PrimitiveUtf8StringFT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * DirectoryString ::= CHOICE { teletexString TeletexString (SIZE (1..MAX)), printableString PrintableString (SIZE
 * (1..MAX)), universalString UniversalString (SIZE (1..MAX)), utf8String UTF8String (SIZE (1..MAX)), bmpString
 * BMPString (SIZE (1..MAX)) }
 * 
 */

public class DirectoryString extends X509Model<Asn1Encodable> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String type = "DirectoryString";

    public static DirectoryString getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        return new DirectoryString(intermediateAsn1Field, identifier);

    }

    private DirectoryString(IntermediateAsn1Field intermediateAsn1Field, String identifier) {
        // Choice
        switch (intermediateAsn1Field.getTagNumber()) {

            // TODO: choice deckt aktuell nur 3 von 5 möglichen Typen ab

            case 20: // TeletexString - T61String
                asn1 = (Asn1PrimitiveT61String) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
                    Asn1PrimitiveT61StringFT.class, identifier, type);
                break;

            case 19: // PrintableString
                asn1 = (Asn1PrimitivePrintableString) X509Translator.translateSingleIntermediateField(
                    intermediateAsn1Field, Asn1PrimitivePrintableStringFT.class, identifier, type);
                break;

            case 28: // UniversalString
                LOGGER.warn("Not Implemented: GeneralName -> Parsing Tag 28 'UniversalString'");
                break;

            case 12: // UTF8String
                asn1 = (Asn1PrimitiveUtf8String) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
                    Asn1PrimitiveUtf8StringFT.class, identifier, type);
                break;

            case 22: // IA5String - this is not defined for DirectoryString but for example the EE Certification Centre
                     // Root CA contains such IA5String for an email
                asn1 = (Asn1PrimitiveIa5String) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
                    Asn1PrimitiveIa5StringFT.class, identifier, type);
                break;

            case 30: // BMPString
                LOGGER.warn("Not Implemented: GeneralName -> Parsing Tag 30 'BMPString'");
                break;

            default:
                LOGGER.warn("Parser Error: DirectoryString -> Default Case triggerd; no Parser defined for Tag Number: "
                    + intermediateAsn1Field.getTagNumber());
        }

    }

}
