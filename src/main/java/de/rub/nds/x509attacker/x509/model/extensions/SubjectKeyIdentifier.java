/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model.extensions;

import de.rub.nds.asn1.model.Asn1OctetString;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.extension.SubjectKeyIdentifierConfig;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.handler.extension.SubjectKeyIdentifierHandler;
import de.rub.nds.x509attacker.x509.model.Extension;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.parser.extension.SubjectKeyIdentifierParser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.extension.SubjectKeyIdentifierPreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * SubjectKeyIdentifier ::= KeyIdentifier
 *
 * <p>KeyIdentifier ::= OCTET STRING
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SubjectKeyIdentifier extends Extension<SubjectKeyIdentifierConfig> {

    @HoldsModifiableVariable private Asn1OctetString keyIdentifier;

    private SubjectKeyIdentifier() {
        super(null);
    }

    public SubjectKeyIdentifier(String identifier) {
        super(identifier);
        keyIdentifier = new Asn1OctetString("keyIdentifier");
    }

    public Asn1OctetString getKeyIdentifier() {
        return keyIdentifier;
    }

    public void setKeyIdentifier(Asn1OctetString keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new SubjectKeyIdentifierHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new SubjectKeyIdentifierParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser, SubjectKeyIdentifierConfig config) {
        return new SubjectKeyIdentifierPreparator(chooser, this, config);
    }
}
