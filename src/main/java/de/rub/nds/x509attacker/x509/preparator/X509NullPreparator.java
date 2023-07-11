/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.x509attacker.chooser.X509Chooser;

public class X509NullPreparator extends X509Asn1FieldPreparator<Asn1Null> {

    public X509NullPreparator(X509Chooser chooser, Asn1Null field) {
        super(chooser, field);
    }

    @Override
    protected byte[] encodeContent() {
        return new byte[0];
    }
}
