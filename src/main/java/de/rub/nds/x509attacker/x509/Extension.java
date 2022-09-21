/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509;

import de.rub.nds.asn1.model.Asn1Boolean;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1BooleanFT;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1ObjectIdentifierFT;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1SequenceFT;

/**
 *
 * Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING -- contains
 * the DER encoding of an ASN.1 value -- corresponding to the extension type identified -- by extnID }
 *
 */
public class Extension extends X509Model<Asn1Sequence> {

    private static final String type = "Extension";

    public Asn1ObjectIdentifier extnID;
    public Asn1Boolean critical;
    public ExtnValue extnValue;

    public static Extension getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        return new Extension(intermediateAsn1Field, identifier);

    }

    private Extension(IntermediateAsn1Field intermediateAsn1Field, String identifier) {
        asn1 = (Asn1Sequence) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
            Asn1SequenceFT.class, identifier, type);

        int index = 0;

        // extnID
        extnID = (Asn1ObjectIdentifier) X509Translator.translateSingleIntermediateField(
            intermediateAsn1Field.getChildren().get(index++), Asn1ObjectIdentifierFT.class, "extnID", "");
        asn1.addChild(extnID);

        // critical - can be optional
        if (intermediateAsn1Field.getChildren().size() == 3) {
            critical = (Asn1Boolean) X509Translator.translateSingleIntermediateField(
                intermediateAsn1Field.getChildren().get(index++), Asn1BooleanFT.class, "critical", "");
            asn1.addChild(critical);
        }

        // extnValue
        // TODO: depending on extnID the Encapsulating Bit String has to be parsed
        // extnValue = (Asn1EncapsulatingOctetString)
        // X509Translator.translateSingleIntermediateField(intermediateAsn1Field.getChildren().get(index++),
        // Asn1EncapsulatingOctetStringFT.class, "extnValue", "");
        extnValue =
            ExtnValue.getInstance(intermediateAsn1Field.getChildren().get(index++), "extnValue", extnID.getValue());
        asn1.addChild(extnValue.asn1);
    }

}
