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
import de.rub.nds.x509attacker.config.extension.SubjectDirectoryAttributesConfig;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.model.Extension;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.extension.SubjectDirectoryAttributesPreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * id-ce-subjectDirectoryAttributes OBJECT IDENTIFIER ::= { id-ce 9 }
 *
 * <p>SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SubjectDirectoryAttributes extends Extension<SubjectDirectoryAttributesConfig> {

    @HoldsModifiableVariable private Asn1UnknownSequence attributes;

    private SubjectDirectoryAttributes() {
        super(null);
    }

    public SubjectDirectoryAttributes(String identifier) {
        super(identifier);

        attributes = new Asn1UnknownSequence("attributes");
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
    public X509Preparator getPreparator(
            X509Chooser chooser, SubjectDirectoryAttributesConfig config) {
        return new SubjectDirectoryAttributesPreparator(chooser, this, config);
    }

    public Asn1UnknownSequence getAttributes() {
        return attributes;
    }

    public void setAttributes(Asn1UnknownSequence attributes) {
        this.attributes = attributes;
    }
}
