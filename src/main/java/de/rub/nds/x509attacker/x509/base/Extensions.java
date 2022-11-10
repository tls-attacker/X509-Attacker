/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Sequence;
import java.util.List;

/**
 *
 * Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
 *
 *
 */
public class Extensions extends Asn1Sequence {

    public List<Extension> extension;

    private Extensions(String identifier) {
        this.setIdentifier(identifier);
    }

}
