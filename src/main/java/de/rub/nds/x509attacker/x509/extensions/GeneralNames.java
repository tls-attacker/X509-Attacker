/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.handler.Handler;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;

/** GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName */

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class GeneralNames extends Asn1Sequence<X509Chooser> {

    @XmlElementWrapper @XmlElementRef @HoldsModifiableVariable
    private List<GeneralName> generalName;

    private GeneralNames() {
        super(null);
    }
    
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

    @Override
    public Handler getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
