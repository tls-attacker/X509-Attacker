/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.GeneralName;

public class GeneralNamePreparator implements X509Preparator {

    private final GeneralName generalName;
    private final X509Chooser chooser;

    public GeneralNamePreparator(X509Chooser chooser, GeneralName generalName) {
        this.generalName = generalName;
        this.chooser = chooser;
    }

    @Override
    public void prepare() {

        generalName.makeSelection();
    }
}
