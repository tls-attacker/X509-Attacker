/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.model.Asn1Choice;

/**
 *
 * Explicit Container for GeneralName
 *
 */
public class ExplicitGeneralName extends Asn1Choice {

    private GeneralName generalName;

    private ExplicitGeneralName(String identifier) {
        super(identifier);
    }

}
