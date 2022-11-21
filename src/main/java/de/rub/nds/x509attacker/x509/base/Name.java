/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import java.util.List;
import org.apache.commons.lang3.tuple.Pair;

/**
 *
 * Name ::= CHOICE { -- only one possibility for now -- rdnSequence RDNSequence }
 *
 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 */
public class Name extends Asn1Sequence {

    @HoldsModifiableVariable
    private RelativeDistinguishedName relativeDistinguishedName;

    public Name(String identifier) {
        super(identifier);
        relativeDistinguishedName = new RelativeDistinguishedName("relativeDistinguishedName");
    }

    public Name(String identifier, List<Pair<X500AttributeType, String>> attributeList) {
        super(identifier);
        relativeDistinguishedName = new RelativeDistinguishedName("relativeDistinguishedName", attributeList);
    }

    public RelativeDistinguishedName getRelativeDistinguishedName() {
        return relativeDistinguishedName;
    }

    public void setRelativeDistinguishedName(RelativeDistinguishedName relativeDistinguishedName) {
        this.relativeDistinguishedName = relativeDistinguishedName;
    }
}
