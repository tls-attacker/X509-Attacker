/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * ReasonFlags ::= BIT STRING { unused (0), keyCompromise (1), cACompromise (2), affiliationChanged
 * (3), superseded (4), cessationOfOperation (5), certificateHold (6), privilegeWithdrawn (7),
 * aACompromise (8) }
 */
public class ReasonFlags extends Asn1PrimitiveBitString {

    private static final Logger LOGGER = LogManager.getLogger();

    public ReasonFlags(String identifier) {
        super(identifier);
    }
}
