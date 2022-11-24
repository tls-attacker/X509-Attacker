/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Explicit;
import de.rub.nds.asn1.model.Asn1Integer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * Version ::= INTEGER {v1(0), v2(1), v3(2) }
 *
 */
public class Version extends Asn1Explicit {

    private static final Logger LOGGER = LogManager.getLogger();

    public Version(String identifier) {
        super(identifier, new Asn1Integer("value"));

    }
}
