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
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509DhParameters;
import de.rub.nds.x509attacker.x509.preparator.X509ContainerPreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;

public class X509DhParameterPreparator extends X509ContainerPreparator<X509DhParameters>
        implements X509Preparator {

    public X509DhParameterPreparator(X509Chooser chooser, X509DhParameters parameters) {
        super(chooser, parameters);
    }

    @Override
    public void prepareSubComponents() {
        field.getG().setValue(chooser.getConfig().getDhGenerator());
        field.getP().setValue(chooser.getConfig().getDhModulus());
    }
}
