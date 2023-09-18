/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.handler;

import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.x509.model.SubjectPublicKeyAlgorithmIdentifier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SubjectPublicKeyAlgorithmIdentifierHandler
        extends X509FieldHandler<SubjectPublicKeyAlgorithmIdentifier> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SubjectPublicKeyAlgorithmIdentifierHandler(
            X509Chooser chooser, SubjectPublicKeyAlgorithmIdentifier identifier) {
        super(chooser, identifier);
    }

    @Override
    public void adjustContextAfterParse() {
        adjustContext();
    }

    @Override
    public void adjustContextAfterPrepare() {
        adjustContext();
    }

    public void adjustContext() {
        ObjectIdentifier objectIdentifier = component.getAlgorithm().getValueAsOid();
        LOGGER.debug("ObjectIdentifier: {}", objectIdentifier);
        context.setSubjectPublicKeyType(
                X509PublicKeyType.decodeFromOidBytes(objectIdentifier.getEncoded()));
    }
}
