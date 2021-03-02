/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1SequenceFT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * EDIPartyName ::= SEQUENCE { nameAssigner [0] DirectoryString OPTIONAL, partyName [1] DirectoryString } }
 */
public class EDIPartyName extends X509Model<Asn1Sequence> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String type = "EDIPartyName";

    public DirectoryString nameAssigner;
    public DirectoryString partyName;

    public static EDIPartyName getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        return new EDIPartyName(intermediateAsn1Field, identifier, false);
    }

    public static EDIPartyName getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier,
        boolean implicit) {

        return new EDIPartyName(intermediateAsn1Field, identifier, implicit);
    }

    private EDIPartyName(IntermediateAsn1Field intermediateAsn1Field, String identifier, boolean implicit) {
        asn1 = (Asn1Sequence) X509Translator.translateSingleIntermediateField(implicit, intermediateAsn1Field,
            Asn1SequenceFT.class, identifier, type);

        int index = 0;

        // nameAssigner - can be optional
        if (intermediateAsn1Field.getChildren().get(index).getTagNumber() == 0) {
            nameAssigner =
                DirectoryString.getInstance(intermediateAsn1Field.getChildren().get(index++), "nameAssigner");
            asn1.addChild(nameAssigner.asn1);
        }

        // partyName
        partyName = DirectoryString.getInstance(intermediateAsn1Field.getChildren().get(index++), "partyName");
        asn1.addChild(partyName.asn1);

    }

}
