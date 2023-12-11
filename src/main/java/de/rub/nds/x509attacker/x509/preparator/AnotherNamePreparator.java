/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.AnotherName;

public class AnotherNamePreparator extends X509ContainerPreparator<AnotherName> {

    public AnotherNamePreparator(X509Chooser chooser, AnotherName otherName) {
        super(chooser, otherName);
    }

    @Override
    public void prepareSubComponents() {
        throw new UnsupportedOperationException("AnotherName not yet implemented for creation");
    }

    @Override
    public byte[] encodeChildrenContent() {
        throw new UnsupportedOperationException("Unimplemented method 'encodeChildren'");
    }
}
