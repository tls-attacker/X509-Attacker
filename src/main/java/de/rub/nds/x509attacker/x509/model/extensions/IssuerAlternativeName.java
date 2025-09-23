/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model.extensions;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.extension.IssuerAlternativeNameConfig;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.model.Extension;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.preparator.extension.IssuerAlternativeNamePreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/** IssuerAltName ::= GeneralNames */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class IssuerAlternativeName extends Extension<IssuerAlternativeNameConfig> {

    @HoldsModifiableVariable private GeneralNames issuerAltName;

    private IssuerAlternativeName() {
        super(null);
    }

    public IssuerAlternativeName(String identifier) {
        super(identifier);

        issuerAltName = new GeneralNames("issuerAltName");
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
    public X509Preparator getPreparator(X509Chooser chooser, IssuerAlternativeNameConfig config) {
        return new IssuerAlternativeNamePreparator(chooser, this, config);
    }

    public GeneralNames getIssuerAltName() {
        return issuerAltName;
    }

    public void setIssuerAltName(GeneralNames issuerAltName) {
        this.issuerAltName = issuerAltName;
    }
}
