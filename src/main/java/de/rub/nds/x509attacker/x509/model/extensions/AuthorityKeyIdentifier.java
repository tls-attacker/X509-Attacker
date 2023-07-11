/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model.extensions;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1OctetString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.model.X509Component;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
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
public class AuthorityKeyIdentifier extends Asn1Sequence implements X509Component {

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
