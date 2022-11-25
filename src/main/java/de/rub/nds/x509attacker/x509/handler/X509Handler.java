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

public abstract class X509Handler {

    protected final X509Chooser chooser;

    public X509Handler(X509Chooser chooser) {
        this.chooser = chooser;
    }

    public abstract void adjustContext();
}
