/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.handler.Handler;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.SubjectPublicKeyAlgorithmIdentifierHandler;
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
    public Handler getHandler(X509Chooser chooser) {
        return new SubjectPublicKeyAlgorithmIdentifierHandler(chooser, this);
    }
}
