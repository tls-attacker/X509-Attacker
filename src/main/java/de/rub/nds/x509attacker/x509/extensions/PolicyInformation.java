/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * PolicyInformation ::= SEQUENCE { policyIdentifier CertPolicyId, policyQualifiers SEQUENCE SIZE
 * (1..MAX) OF PolicyQualifierInfo OPTIONAL }
 *
 * <p>CertPolicyId ::= OBJECT IDENTIFIER
 */
public class PolicyInformation extends Asn1Sequence {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable
    private Asn1ObjectIdentifier policyIdentifier; // CertPolicyId ::= OBJECT IDENTIFIER

    @HoldsModifiableVariable private PolicyQualifiers policyQualifiers;

    public PolicyInformation(String identifier) {
        super(identifier);
        policyIdentifier = new Asn1ObjectIdentifier("policyIdentifier");
        policyQualifiers = new PolicyQualifiers("policyQualifiers");
        addChild(policyIdentifier);
        addChild(policyQualifiers);
    }

    public Asn1ObjectIdentifier getPolicyIdentifier() {
        return policyIdentifier;
    }

    public void setPolicyIdentifier(Asn1ObjectIdentifier policyIdentifier) {
        this.policyIdentifier = policyIdentifier;
    }

    public PolicyQualifiers getPolicyQualifiers() {
        return policyQualifiers;
    }

    public void setPolicyQualifiers(PolicyQualifiers policyQualifiers) {
        this.policyQualifiers = policyQualifiers;
    }
}
