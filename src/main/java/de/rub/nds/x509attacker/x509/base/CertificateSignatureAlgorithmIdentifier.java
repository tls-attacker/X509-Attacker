/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.CertificateSignatureAlgorithmIdentifierHandler;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.preparator.CertificateSignatureAlgorithmIdentifierPreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class CertificateSignatureAlgorithmIdentifier extends AlgorithmIdentifier {

    public CertificateSignatureAlgorithmIdentifier(String identifier) {
        super(identifier);
    }

    private CertificateSignatureAlgorithmIdentifier() {
        super(null);
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new CertificateSignatureAlgorithmIdentifierHandler(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new CertificateSignatureAlgorithmIdentifierPreparator(chooser, this);
    }
}
