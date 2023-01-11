/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.handler.publickey.parameters;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.DhValidationParms;
import de.rub.nds.x509attacker.x509.handler.X509Handler;

public class DhValidationParmsHandler extends X509Handler {

    private final DhValidationParms parameters;

    public DhValidationParmsHandler(X509Chooser chooser, DhValidationParms parameters) {
        super(chooser);
        this.parameters = parameters;
    }

    @Override
    public void adjustContext() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
