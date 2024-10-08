/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.parser;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.OrAddress;
import java.io.BufferedInputStream;

public class OrAddressParser extends X509ComponentContainerParser<OrAddress> {

    public OrAddressParser(X509Chooser chooser, OrAddress orAddress) {
        super(chooser, orAddress);
    }

    @Override
    protected void parseSubcomponents(BufferedInputStream inputStream) {
        throw new UnsupportedOperationException("OrAddress not supported for now.");
    }
}
