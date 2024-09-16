/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model.extensions;

import de.rub.nds.asn1.model.Asn1BitString;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.extension.KeyUsageConfig;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.handler.extension.KeyUsageHandler;
import de.rub.nds.x509attacker.x509.model.Extension;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.parser.extension.KeyUsageParser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.extension.KeyUsagePreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * KeyUsage ::= BIT STRING { digitalSignature (0), nonRepudiation (1), -- recent editions of X.509
 * have -- renamed this bit to contentCommitment keyEncipherment (2), dataEncipherment (3),
 * keyAgreement (4), keyCertSign (5), cRLSign (6), encipherOnly (7), decipherOnly (8) }
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyUsage extends Extension<KeyUsageConfig> {

    @HoldsModifiableVariable private Asn1BitString bitString;

    private KeyUsage() {
        super(null);
    }

    public KeyUsage(String identifier) {
        super(identifier);
    }

    public Asn1BitString getBitString() {
        return bitString;
    }

    public void setBitString(Asn1BitString bitString) {
        this.bitString = bitString;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new KeyUsageHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new KeyUsageParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser, KeyUsageConfig config) {
        return new KeyUsagePreparator(chooser, this, config);
    }
}
