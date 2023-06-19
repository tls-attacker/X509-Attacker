/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.publickey;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.publickey.X509X448PublicKey;
import de.rub.nds.x509attacker.x509.preparator.X509ComponentPreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;

public class X448PublicKeyPreparator extends X509ComponentPreparator<X509X448PublicKey>
        implements X509Preparator {
    public X448PublicKeyPreparator(X509Chooser chooser, X509X448PublicKey instance) {
        super(chooser, instance);
    }

    @Override
    public void prepareSubComponents() {
        throw new UnsupportedOperationException("Unimplemented method 'prepareSubComponents'");
    }
}
