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
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.x509.base.SubjectPublicKeyAlgorithmIdentifier;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SubjectPublicKeyAlgorithmIdentifierHandler extends X509Handler {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SubjectPublicKeyAlgorithmIdentifier identifier;

    public SubjectPublicKeyAlgorithmIdentifierHandler(
            X509Chooser chooser, SubjectPublicKeyAlgorithmIdentifier identifier) {
        super(chooser);
        this.identifier = identifier;
    }

    @Override
    public void adjustContext() {
        ObjectIdentifier objectIdentifier =
                new ObjectIdentifier(identifier.getAlgorithm().getValue().getValue());
        LOGGER.debug("ObjectIdentifier: " + objectIdentifier.toString());
        context.setSubjectPublicKeyType(
                X509PublicKeyType.decodeFromOidBytes(objectIdentifier.getEncoded()));
    }
}
