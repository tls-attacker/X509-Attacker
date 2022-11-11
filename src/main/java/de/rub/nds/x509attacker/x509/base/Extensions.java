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
 * Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
 *
 *
 */
public class Extensions extends Asn1Sequence {

    @XmlElementWrapper
    @XmlElementRef
    @HoldsModifiableVariable
    private List<Extension> extensionList;

    public Extensions(String identifier) {
        super(identifier);
        extensionList = new LinkedList<>();
    }

    public List<Extension> getExtensionList() {
        return extensionList;
    }

    public void setExtensionList(List<Extension> extensionList) {
        this.extensionList = extensionList;
    }
}
