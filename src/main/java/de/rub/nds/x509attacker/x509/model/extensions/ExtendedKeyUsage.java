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
import de.rub.nds.x509attacker.config.extension.ExtendedKeyUsageConfig;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.handler.extension.ExtendedKeyUsageHandler;
import de.rub.nds.x509attacker.x509.model.Extension;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.extension.ExtendedKeyUsagePreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 *
 * <p>KeyPurposeId ::= OBJECT IDENTIFIER
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ExtendedKeyUsage extends Extension<ExtendedKeyUsageConfig> {

    @HoldsModifiableVariable private Asn1UnknownSequence keyPurposeIDs;

    private ExtendedKeyUsage() {
        super(null);
    }

    public ExtendedKeyUsage(String identifier) {
        super(identifier);
        keyPurposeIDs = new Asn1UnknownSequence("keyPurposeIDs");
    }

    public Asn1UnknownSequence getKeyPurposeIDs() {
        return keyPurposeIDs;
    }

    public void setKeyPurposeIDs(Asn1UnknownSequence keyPurposeIDs) {
        this.keyPurposeIDs = keyPurposeIDs;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new ExtendedKeyUsageHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser, ExtendedKeyUsageConfig config) {
        return new ExtendedKeyUsagePreparator(chooser, this, config);
    }
}
