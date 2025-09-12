/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model.extensions;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1UnknownSequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.extension.PolicyConstraintsConfig;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.model.Extension;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.extension.PolicyConstraintsPreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * PolicyConstraints ::= SEQUENCE { requireExplicitPolicy [0] SkipCerts OPTIONAL,
 * inhibitPolicyMapping [1] SkipCerts OPTIONAL }
 *
 * <p>SkipCerts ::= INTEGER (0..MAX)
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class PolicyConstraints extends Extension<PolicyConstraintsConfig> {

    // holds all subcomponents
    @HoldsModifiableVariable private Asn1UnknownSequence wrappingSequence;

    @HoldsModifiableVariable private Asn1Integer requireExplicitPolicy;
    @HoldsModifiableVariable private Asn1Integer inhibitPolicyMapping;

    private PolicyConstraints() {
        super(null);
    }

    public PolicyConstraints(String identifier) {
        super(identifier);

        requireExplicitPolicy = new Asn1Integer("requireExplicitPolicy");
        inhibitPolicyMapping = new Asn1Integer("inhibitPolicyMapping");

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
    public X509Preparator getPreparator(X509Chooser chooser, PolicyConstraintsConfig config) {
        return new PolicyConstraintsPreparator(chooser, this, config);
    }

    public Asn1Integer getRequireExplicitPolicy() {
        return requireExplicitPolicy;
    }

    public void setRequireExplicitPolicy(Asn1Integer requireExplicitPolicy) {
        this.requireExplicitPolicy = requireExplicitPolicy;
    }

    public Asn1Integer getInhibitPolicyMapping() {
        return inhibitPolicyMapping;
    }

    public void setInhibitPolicyMapping(Asn1Integer inhibitPolicyMapping) {
        this.inhibitPolicyMapping = inhibitPolicyMapping;
    }

    public Asn1UnknownSequence getWrappingSequence() {
        return wrappingSequence;
    }

    public void setWrappingSequence(Asn1UnknownSequence wrappingSequence) {
        this.wrappingSequence = wrappingSequence;
    }
}
