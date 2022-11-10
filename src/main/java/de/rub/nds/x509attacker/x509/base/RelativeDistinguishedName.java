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
import java.util.List;

/**
 *
 * RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
 *
 */
public class RelativeDistinguishedName extends Asn1Set {

    public List<AttributeTypeAndValue> attributeTypeAndValue;

    public RelativeDistinguishedName(String identifier) {
        this.setIdentifier(identifier);
    }

    public List<AttributeTypeAndValue> getAttributeTypeAndValue() {
        return attributeTypeAndValue;
    }

    public void setAttributeTypeAndValue(List<AttributeTypeAndValue> attributeTypeAndValue) {
        this.attributeTypeAndValue = attributeTypeAndValue;
    }
}
