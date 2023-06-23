/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.publickey.parameters;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509DhValidationParms;
import de.rub.nds.x509attacker.x509.preparator.X509ContainerPreparator;

public class X509DhValidationParmsPreparator
        extends X509ContainerPreparator<X509DhValidationParms> {

    public X509DhValidationParmsPreparator(
            X509Chooser chooser, X509DhValidationParms x509DhValidationParms) {
        super(chooser, x509DhValidationParms);
    }

    @Override
    public void prepareSubComponents() {
        prepareField(
                field.getPgenCounter(), chooser.getConfig().getDhValidationParameterPgenCounter());
        prepareField(
                field.getSeed(), chooser.getConfig().getDhValidationParameterSeed(), (byte) 0x00);
    }
}
