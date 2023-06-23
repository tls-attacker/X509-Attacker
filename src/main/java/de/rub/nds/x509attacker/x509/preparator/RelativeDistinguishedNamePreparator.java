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
import de.rub.nds.x509attacker.x509.model.RelativeDistinguishedName;

public class RelativeDistinguishedNamePreparator
        extends X509ContainerPreparator<RelativeDistinguishedName> {

    public RelativeDistinguishedNamePreparator(
            X509Chooser chooser, RelativeDistinguishedName relativeDistinguishedName) {
        super(chooser, relativeDistinguishedName);
    }

    @Override
    public void prepareSubComponents() {
        field.getAttributeTypeAndValueList().forEach(atv -> atv.getPreparator(chooser).prepare());
    }
}
