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
import de.rub.nds.x509attacker.x509.model.OrAddress;

public class OrAddressPreparator extends X509ContainerPreparator<OrAddress> {

    public OrAddressPreparator(X509Chooser chooser, OrAddress orAddress) {
        super(chooser, orAddress);
    }

    @Override
    public void prepareSubComponents() {
        throw new UnsupportedOperationException("OrAddress not implemented yet");
    }
}
