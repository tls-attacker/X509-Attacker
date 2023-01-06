/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * SubjectKeyIdentifier ::= KeyIdentifier
 *
 * <p>KeyIdentifier ::= OCTET STRING
 */
public class SubjectKeyIdentifier extends Asn1PrimitiveOctetString<X509Chooser> {

    private static final Logger LOGGER = LogManager.getLogger();

    private SubjectKeyIdentifier(String identifier) {
        super(identifier);
    }
}
