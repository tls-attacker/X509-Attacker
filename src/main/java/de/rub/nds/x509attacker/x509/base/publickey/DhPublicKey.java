/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.base.publickey;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.preparator.Preparator;

public class DhPublicKey extends Asn1Integer implements SubjectPublicKey {

    public DhPublicKey() {
        super("dhPublicKey");
    }

    @Override
    public Preparator getPreparator() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
