/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.Name;
import de.rub.nds.x509attacker.x509.model.RelativeDistinguishedName;

public class NamePreparator extends X509ContainerPreparator<Name> {

    public NamePreparator(X509Chooser chooser, Name name) {
        super(chooser, name);
    }

    @Override
    public void prepareSubComponents() {
        for (RelativeDistinguishedName rdn : field.getRelativeDistinguishedNames()) {
            rdn.getPreparator(chooser).prepare();
        }
    }

    @Override
    public byte[] encodeChildrenContent() {
        return encodeChildren(
                field.getRelativeDistinguishedNames()
                        .toArray(new Asn1Encodable[field.getRelativeDistinguishedNames().size()]));
    }
}
