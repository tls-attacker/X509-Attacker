/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Set;
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.parser.RelativeDistinguishedNameParser;
import java.util.List;
import org.apache.commons.lang3.tuple.Pair;

/** RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue */
public class RelativeDistinguishedName extends Asn1Set {

    public RelativeDistinguishedName(String identifier) {
        super(identifier);
    }

    public RelativeDistinguishedName(
            String identifier, List<Pair<X500AttributeType, String>> attributeList) {
        super(identifier);
        for (Pair<X500AttributeType, String> pair : attributeList) {
            AttributeTypeAndValue attributeTypeAndValue =
                    new AttributeTypeAndValue(
                            pair.getKey()
                                    .getHumanReadableName()
                                    .concat("=")
                                    .concat(pair.getValue()),
                            pair.getKey(),
                            pair.getValue());
            addChild(attributeTypeAndValue);
        }
    }

    @Override
    public Asn1Parser<?> getParser() {
        return new RelativeDistinguishedNameParser(this);
    }
}
