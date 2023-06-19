/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;

public class ExtensionsHandler extends X509Handler {

    public ExtensionsHandler(X509Chooser chooser, Extensions extensions) {}

    @Override
    public void adjustContext() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'adjustContext'");
    }
}
