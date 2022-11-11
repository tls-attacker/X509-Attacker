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
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * Name ::= CHOICE { -- only one possibility for now -- rdnSequence RDNSequence
 * }
 *
 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 */
public class Name extends Asn1Sequence {

    @XmlElementWrapper
    @XmlElementRef
    @HoldsModifiableVariable
    private List<RelativeDistinguishedName> relativeDistinguishedName;

    public Name(String identifier) {
        super(identifier);
        relativeDistinguishedName = new LinkedList<>();
    }

    public List<RelativeDistinguishedName> getRelativeDistinguishedName() {
        return relativeDistinguishedName;
    }

    public void setRelativeDistinguishedName(List<RelativeDistinguishedName> relativeDistinguishedName) {
        this.relativeDistinguishedName = relativeDistinguishedName;
    }
}
