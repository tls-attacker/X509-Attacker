/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.handler;

import de.rub.nds.x509attacker.chooser.X509Chooser;

/**
 * This handler does not update anything. A lot of X509 components have no reason to update the
 * context.
 */
public class NullX509Handler extends X509Handler {

    public NullX509Handler(X509Chooser chooser) {
        super(chooser);
    }

    @Override
    public void adjustContext() {}
}
