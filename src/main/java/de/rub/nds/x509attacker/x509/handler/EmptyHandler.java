/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.handler;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.X509Component;

public class EmptyHandler<Type extends X509Component> extends X509FieldHandler<Type> {

    public EmptyHandler(X509Chooser chooser, Type component) {
        super(chooser, component);
    }

    @Override
    public void adjustContext() {
        // Nothing to do
    }
}
