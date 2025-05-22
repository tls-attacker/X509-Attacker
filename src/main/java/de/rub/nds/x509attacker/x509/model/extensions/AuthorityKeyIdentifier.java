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
import de.rub.nds.asn1.model.Asn1OctetString;
import de.rub.nds.asn1.model.Asn1UnknownSequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.extension.AuthorityKeyIdentifierConfig;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.handler.extension.AuthorityKeyIdentifierHandler;
import de.rub.nds.x509attacker.x509.model.Extension;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.parser.extension.AuthorityKeyIdentifierParser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.extension.AuthorityKeyIdentifierPreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] KeyIdentifier OPTIONAL,
 * authorityCertIssuer [1] GeneralNames OPTIONAL, authorityCertSerialNumber [2]
 * CertificateSerialNumber OPTIONAL }
 *
 * <p>KeyIdentifier ::= OCTET STRING
 *
 * <p>CertificateSerialNumber ::= INTEGER
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class AuthorityKeyIdentifier extends Extension<AuthorityKeyIdentifierConfig> {

    // holds all subcomponents
    @HoldsModifiableVariable private Asn1UnknownSequence wrappingSequence;

    @HoldsModifiableVariable private Asn1OctetString keyIdentifier;

    @HoldsModifiableVariable private GeneralNames authorityCertIssuer;

    @HoldsModifiableVariable private Asn1Integer authorityCertSerialNumber;

    private AuthorityKeyIdentifier() {
        super(null);
    }

    public AuthorityKeyIdentifier(String identifier) {
        super(identifier);
        keyIdentifier = new Asn1OctetString("keyIdentifier");
        authorityCertIssuer = new GeneralNames("authorityCertIssuer");
        authorityCertSerialNumber = new Asn1Integer("authorityCertSerialNumber");
        wrappingSequence = new Asn1UnknownSequence("wrappingSequence");
    }

    public Asn1OctetString getKeyIdentifier() {
        return keyIdentifier;
    }

    public void setKeyIdentifier(Asn1OctetString keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
    }

    public GeneralNames getAuthorityCertIssuer() {
        return authorityCertIssuer;
    }

    public void setAuthorityCertIssuer(GeneralNames authorityCertIssuer) {
        this.authorityCertIssuer = authorityCertIssuer;
    }

    public Asn1Integer getAuthorityCertSerialNumber() {
        return authorityCertSerialNumber;
    }

    public void setAuthorityCertSerialNumber(Asn1Integer authorityCertSerialNumber) {
        this.authorityCertSerialNumber = authorityCertSerialNumber;
    }

    public Asn1UnknownSequence getWrappingSequence() {
        return wrappingSequence;
    }

    public void setWrappingSequence(Asn1UnknownSequence wrappingSequence) {
        this.wrappingSequence = wrappingSequence;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new AuthorityKeyIdentifierHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new AuthorityKeyIdentifierParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser, AuthorityKeyIdentifierConfig config) {
        return new AuthorityKeyIdentifierPreparator(chooser, this, config);
    }
}
