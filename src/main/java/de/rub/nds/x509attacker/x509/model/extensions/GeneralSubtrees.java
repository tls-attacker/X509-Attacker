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
import de.rub.nds.asn1.model.Asn1UnknownSequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.model.X509Component;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.extension.GeneralSubtreesPreparator;
import jakarta.xml.bind.annotation.XmlAnyElement;
import java.util.ArrayList;
import java.util.List;

public class GeneralSubtrees extends Asn1Sequence implements X509Component {
    // holds all subcomponents
    @HoldsModifiableVariable private Asn1UnknownSequence wrappingSequence;

    @HoldsModifiableVariable
    @XmlAnyElement(lax = true)
    private List<GeneralSubtree> generalSubtrees;

    public GeneralSubtrees() {
        super(null);
    }

    public GeneralSubtrees(String identifier) {
        super(identifier);
        generalSubtrees = new ArrayList<>();
        wrappingSequence = new Asn1UnknownSequence("generalSubtrees");
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
        return new GeneralSubtreesPreparator(chooser, this);
    }

    public Asn1UnknownSequence getWrappingSequence() {
        return wrappingSequence;
    }

    public void setWrappingSequence(Asn1UnknownSequence wrappingSequence) {
        this.wrappingSequence = wrappingSequence;
    }

    public List<GeneralSubtree> getGeneralSubtrees() {
        return generalSubtrees;
    }

    public void setGeneralSubtrees(List<GeneralSubtree> generalSubtrees) {
        this.generalSubtrees = generalSubtrees;
    }
}
