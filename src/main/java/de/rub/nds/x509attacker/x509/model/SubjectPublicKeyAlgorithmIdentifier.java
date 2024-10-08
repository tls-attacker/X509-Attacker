/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.SubjectPublicKeyAlgorithmIdentifierHandler;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.SubjectPublicKeyAlgorithmIdentifierParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.SubjectPublicKeyAlgorithmIdentifierPreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SubjectPublicKeyAlgorithmIdentifier extends AlgorithmIdentifier {

    private SubjectPublicKeyAlgorithmIdentifier() {
        super(null);
    }

    public SubjectPublicKeyAlgorithmIdentifier(String identifier) {
        super(identifier);
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new SubjectPublicKeyAlgorithmIdentifierHandler(chooser, this);
    }

    @Override
    public final X509Parser getParser(X509Chooser chooser) {
        return new SubjectPublicKeyAlgorithmIdentifierParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new SubjectPublicKeyAlgorithmIdentifierPreparator(chooser, this);
    }
}
