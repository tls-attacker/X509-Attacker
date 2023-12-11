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
import de.rub.nds.x509attacker.x509.model.EdiPartyName;

public class EdiPartyNamePreparator extends X509ContainerPreparator<EdiPartyName> {

    public EdiPartyNamePreparator(X509Chooser chooser, EdiPartyName ediPartyName) {
        super(chooser, ediPartyName);
    }

    @Override
    public void prepareSubComponents() {
        throw new UnsupportedOperationException("EdiPartyName is not yet implemented");
    }

    @Override
    public byte[] encodeChildrenContent() {
        throw new UnsupportedOperationException("Unimplemented method 'encodeChildrenContent'");
    }
}
