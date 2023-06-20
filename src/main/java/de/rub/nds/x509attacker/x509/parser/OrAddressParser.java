/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.OrAddress;
import java.io.PushbackInputStream;

public class OrAddressParser extends X509ComponentContainerParser<OrAddress> {

    public OrAddressParser(X509Chooser chooser, OrAddress orAddress) {
        super(chooser, orAddress);
    }

    @Override
    protected void parseSubcomponents(PushbackInputStream inputStream) {
        throw new UnsupportedOperationException("Unimplemented method 'parseSubcomponents'");
    }
}
