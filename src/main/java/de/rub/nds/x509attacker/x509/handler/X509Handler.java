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
import de.rub.nds.x509attacker.x509.base.X509Component;

public abstract class X509Handler<Component extends X509Component> {

    protected final Component component;

    protected final X509Chooser chooser;

    public X509Handler(Component component, X509Chooser chooser) {
        this.component = component;
        this.chooser = chooser;
    }

    public abstract void adjustContext();

    public abstract void adjustRuntimeContext();

}
