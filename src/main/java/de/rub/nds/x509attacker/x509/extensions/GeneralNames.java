/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import java.util.LinkedList;
import java.util.List;

/**
 *
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 *
 */
public class GeneralNames extends Asn1Sequence {

    @XmlElementWrapper
    @XmlElementRef
    @HoldsModifiableVariable
    private List<GeneralName> generalName;

    public GeneralNames(String identifier) {
        super(identifier);
        generalName = new LinkedList<>();
    }

    public List<GeneralName> getGeneralName() {
        return generalName;
    }

    public void setGeneralName(List<GeneralName> generalName) {
        this.generalName = generalName;
    }
}
