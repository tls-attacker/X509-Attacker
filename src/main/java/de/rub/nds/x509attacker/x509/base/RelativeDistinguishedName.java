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
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import java.util.LinkedList;
import java.util.List;
import org.apache.commons.lang3.tuple.Pair;

/**
 *
 * RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
 *
 */
public class RelativeDistinguishedName extends Asn1Set {

    @XmlElementWrapper
    @XmlElementRef
    @HoldsModifiableVariable
    private List<AttributeTypeAndValue> attributeTypeAndValueList;

    public RelativeDistinguishedName(String identifier) {
        super(identifier);
        attributeTypeAndValueList = new LinkedList<>();
    }

    public RelativeDistinguishedName(String identifier, List<Pair<X500AttributeType, String>> attributeList) {
        super(identifier);
        attributeTypeAndValueList = new LinkedList<>();
        for (Pair<X500AttributeType, String> pair : attributeList) {
            AttributeTypeAndValue attributeTypeAndValue =
                new AttributeTypeAndValue(pair.getKey().getHumanReadableName().concat("=").concat(pair.getValue()));
            attributeTypeAndValueList.add(attributeTypeAndValue);
        }

    }

    public List<AttributeTypeAndValue> getAttributeTypeAndValueList() {
        return attributeTypeAndValueList;
    }

    public void setAttributeTypeAndValueList(List<AttributeTypeAndValue> attributeTypeAndValueList) {
        this.attributeTypeAndValueList = attributeTypeAndValueList;
    }
}
