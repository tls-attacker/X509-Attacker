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
import de.rub.nds.x509attacker.config.extension.PolicyMappingsConfig;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.model.Extension;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.extension.PolicyMappingsPreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * id-ce-policyMappings OBJECT IDENTIFIER ::= { id-ce 33 }
 *
 * <p>PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE { issuerDomainPolicy CertPolicyId,
 * subjectDomainPolicy CertPolicyId }
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class PolicyMappings extends Extension<PolicyMappingsConfig> {

    @HoldsModifiableVariable private Asn1UnknownSequence policyMappings;

    public PolicyMappings() {
        super(null);
    }

    public PolicyMappings(String identifier) {
        super(identifier);

        policyMappings = new Asn1UnknownSequence("policyMappings");
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
    public X509Preparator getPreparator(X509Chooser chooser, PolicyMappingsConfig config) {
        return new PolicyMappingsPreparator(chooser, this, config);
    }

    public Asn1UnknownSequence getPolicyMappings() {
        return policyMappings;
    }

    public void setPolicyMappings(Asn1UnknownSequence policyMappings) {
        this.policyMappings = policyMappings;
    }
}
