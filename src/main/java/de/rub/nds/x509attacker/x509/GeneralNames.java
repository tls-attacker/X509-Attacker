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
import java.util.LinkedList;
import java.util.List;

/**
 * 
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 * 
 */
public class GeneralNames extends X509Model<Asn1Sequence> {

    private static final String type = "GeneralNames";

    public List<GeneralName> generalName;

    public static GeneralNames getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        return new GeneralNames(intermediateAsn1Field, identifier);

    }

    private GeneralNames(IntermediateAsn1Field intermediateAsn1Field, String identifier) {
        asn1 = (Asn1Sequence) X509Translator.translateSingleIntermediateField(intermediateAsn1Field,
            Asn1SequenceFT.class, identifier, type);

        generalName = new LinkedList<>();
        int index = 0;
        for (IntermediateAsn1Field interFieldChild : intermediateAsn1Field.getChildren()) {
            generalName.add(GeneralName.getInstance(interFieldChild, "generalName" + index++));
            asn1.addChild(generalName.get(generalName.size() - 1).asn1);
        }

    }

}
