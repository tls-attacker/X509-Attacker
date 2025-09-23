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
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.extension.InhibitAnyPolicyConfig;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.model.Extension;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.extension.InhibitAnyPolicyPreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/** InhibitAnyPolicy ::= SkipCerts SkipCerts ::= INTEGER (0..MAX) */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class InhibitAnyPolicy extends Extension<InhibitAnyPolicyConfig> {

    @HoldsModifiableVariable private Asn1Integer skipCerts;

    private InhibitAnyPolicy() {
        super(null);
    }

    public InhibitAnyPolicy(String identifier) {
        super(identifier);

        skipCerts = new Asn1Integer("skipCerts");
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
    public X509Preparator getPreparator(X509Chooser chooser, InhibitAnyPolicyConfig config) {
        return new InhibitAnyPolicyPreparator(chooser, this, config);
    }

    public Asn1Integer getSkipCerts() {
        return skipCerts;
    }

    public void setSkipCerts(Asn1Integer skipCerts) {
        this.skipCerts = skipCerts;
    }
}
