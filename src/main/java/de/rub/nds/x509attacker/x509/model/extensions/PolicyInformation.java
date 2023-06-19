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
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.X509Component;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * PolicyInformation ::= SEQUENCE { policyIdentifier CertPolicyId, policyQualifiers SEQUENCE SIZE
 * (1..MAX) OF PolicyQualifierInfo OPTIONAL }
 *
 * <p>CertPolicyId ::= OBJECT IDENTIFIER
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class PolicyInformation extends Asn1Sequence implements X509Component {

    @HoldsModifiableVariable
    private Asn1ObjectIdentifier policyIdentifier; // CertPolicyId ::= OBJECT IDENTIFIER

    @HoldsModifiableVariable private PolicyQualifiers policyQualifiers;

    private PolicyInformation() {
        super(null);
    }

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
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }
}
