/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
 * Name ::= CHOICE { -- only one possibility for now -- rdnSequence RDNSequence }
 * 
 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 * 
 */
public class Name extends X509Model<Asn1Sequence> {

    private static final String type = "Name";

    public List<RelativeDistinguishedName> relativeDistinguishedName;

    public static Name getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier) {

        return new Name(intermediateAsn1Field, identifier, false);
    }

    public static Name getInstance(IntermediateAsn1Field intermediateAsn1Field, String identifier, boolean implicit) {

        return new Name(intermediateAsn1Field, identifier, implicit);
    }

    private Name(IntermediateAsn1Field intermediateAsn1Field, String identifier, boolean implicit) {
        asn1 = (Asn1Sequence) X509Translator.translateSingleIntermediateField(implicit, intermediateAsn1Field,
            Asn1SequenceFT.class, identifier, type);

        relativeDistinguishedName = new LinkedList<>();
        int index = 0;
        for (IntermediateAsn1Field interFieldChild : intermediateAsn1Field.getChildren()) {
            relativeDistinguishedName
                .add(RelativeDistinguishedName.getInstance(interFieldChild, "relativeDistinguishedName" + index++));
            asn1.addChild(relativeDistinguishedName.get(relativeDistinguishedName.size() - 1).asn1);
        }

    }

}
