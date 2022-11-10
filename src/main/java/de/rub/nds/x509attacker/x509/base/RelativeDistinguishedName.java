/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Set;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.X509Translator;
import de.rub.nds.asn1.translator.fieldtranslators.Asn1SetFT;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
 *
 */
public class RelativeDistinguishedName extends X509Model<Asn1Set> {

    private static final String type = "RelativeDistinguishedName";

    public List<AttributeTypeAndValue> attributeTypeAndValue;

    public static RelativeDistinguishedName getInstance(IntermediateAsn1Field intermediateAsn1Field,
        String identifier) {

        return new RelativeDistinguishedName(intermediateAsn1Field, identifier);

    }

    private RelativeDistinguishedName(IntermediateAsn1Field intermediateAsn1Field, String identifier) {
        asn1 = (Asn1Set) X509Translator.translateSingleIntermediateField(intermediateAsn1Field, Asn1SetFT.class,
            identifier, type);

        attributeTypeAndValue = new LinkedList<>();
        int index = 0;
        for (IntermediateAsn1Field interFieldChild : intermediateAsn1Field.getChildren()) {
            attributeTypeAndValue
                .add(AttributeTypeAndValue.getInstance(interFieldChild, "attributeTypeAndValue" + index++));
            asn1.addChild(attributeTypeAndValue.get(attributeTypeAndValue.size() - 1).asn1);
        }

    }

}
