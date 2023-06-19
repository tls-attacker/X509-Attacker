/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.handler;

import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.x509.model.CertificateSignatureAlgorithmIdentifier;

public class CertificateSignatureAlgorithmIdentifierHandler
        extends X509FieldHandler<CertificateSignatureAlgorithmIdentifier> {

    public CertificateSignatureAlgorithmIdentifierHandler(
            X509Chooser chooser, CertificateSignatureAlgorithmIdentifier identifier) {
        super(chooser, identifier);
    }

    @Override
    public void adjustContext() {
        context.setSubjectSignatureAlgorithm(
                X509SignatureAlgorithm.decodeFromOidBytes(
                        new ObjectIdentifier(component.getAlgorithm().getValue().getValue())
                                .getEncoded()));
    }
}
