/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model.extensions;

import de.rub.nds.asn1.model.Asn1UnknownSequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.extension.NameConstraintsConfig;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.model.Extension;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.extension.NameConstraintsPreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class NameConstraints extends Extension<NameConstraintsConfig> {

    // holds all subcomponents
    @HoldsModifiableVariable private Asn1UnknownSequence wrappingSequence;

    @HoldsModifiableVariable private GeneralSubtrees permittedSubtrees;
    @HoldsModifiableVariable private GeneralSubtrees excludedSubtrees;

    private NameConstraints() {
        super(null);
    }

    public NameConstraints(String identifier) {
        super(identifier);

        permittedSubtrees = new GeneralSubtrees("permittedSubtrees");
        excludedSubtrees = new GeneralSubtrees("excludedSubtrees");
        wrappingSequence = new Asn1UnknownSequence("wrappingSequence");
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
    public X509Preparator getPreparator(X509Chooser chooser, NameConstraintsConfig config) {
        return new NameConstraintsPreparator(chooser, this, config);
    }

    public Asn1UnknownSequence getWrappingSequence() {
        return wrappingSequence;
    }

    public void setWrappingSequence(Asn1UnknownSequence wrappingSequence) {
        this.wrappingSequence = wrappingSequence;
    }

    public GeneralSubtrees getPermittedSubtrees() {
        return permittedSubtrees;
    }

    public void setPermittedSubtrees(GeneralSubtrees permittedSubtrees) {
        this.permittedSubtrees = permittedSubtrees;
    }

    public GeneralSubtrees getExcludedSubtrees() {
        return excludedSubtrees;
    }

    public void setExcludedSubtrees(GeneralSubtrees excludedSubtrees) {
        this.excludedSubtrees = excludedSubtrees;
    }
}
