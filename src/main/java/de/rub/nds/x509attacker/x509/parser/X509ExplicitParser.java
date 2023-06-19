/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import java.io.PushbackInputStream;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.ExplicitExtensions;
import de.rub.nds.x509attacker.x509.model.X509ExplicitComponent;

public class X509ExplicitParser extends X509ComponentParser<X509ExplicitComponent> {

    public X509ExplicitParser(X509Chooser chooser, X509ExplicitComponent explicitExtensions) {
        super(chooser, explicitExtensions);
    }

    @Override
    protected void parseContent(PushbackInputStream inputStream) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'parseContent'");
    }
}
