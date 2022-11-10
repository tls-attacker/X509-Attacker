/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.model.Asn1Sequence;
import java.util.List;

/**
 *
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 *
 */
public class GeneralNames extends Asn1Sequence {

    private static final String type = "GeneralNames";

    public List<GeneralName> generalName;

    private GeneralNames(String identifier) {
        this.setIdentifier(identifier);
    }

    public List<GeneralName> getGeneralName() {
        return generalName;
    }

    public void setGeneralName(List<GeneralName> generalName) {
        this.generalName = generalName;
    }
}
