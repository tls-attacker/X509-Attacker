/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model.extensions;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.model.GeneralName;
import de.rub.nds.x509attacker.x509.model.X509Component;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.extension.GeneralNamesPreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAnyElement;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;

/** GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class GeneralNames extends Asn1Sequence implements X509Component {

    @HoldsModifiableVariable
    @XmlAnyElement(lax = true)
    private List<GeneralName> generalNames;

    private GeneralNames() {
        super(null);
    }

    public GeneralNames(String identifier) {
        super(identifier);
        generalNames = new LinkedList<>();
    }

    public GeneralNames(String identifier, int implicitTagNumber) {
        super(identifier, implicitTagNumber);
        generalNames = new LinkedList<>();
    }

    public List<GeneralName> getGeneralNames() {
        return generalNames;
    }

    public void setGeneralNames(List<GeneralName> generalNames) {
        this.generalNames = generalNames;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new GeneralNamesPreparator(chooser, this);
    }
}
