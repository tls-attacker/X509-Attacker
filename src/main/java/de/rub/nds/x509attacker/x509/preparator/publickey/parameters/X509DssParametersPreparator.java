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
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509DssParameters;
import de.rub.nds.x509attacker.x509.preparator.X509ContainerPreparator;

public class X509DssParametersPreparator extends X509ContainerPreparator<X509DssParameters> {

    public X509DssParametersPreparator(X509Chooser chooser, X509DssParameters parameters) {
        super(chooser, parameters);
    }

    @Override
    public void prepareSubComponents() {
        prepareField(field.getQ(), chooser.getConfig().getDsaPrimeQ());
        prepareField(field.getG(), chooser.getConfig().getDsaGenerator());
        prepareField(field.getP(), chooser.getConfig().getDsaPrimeP());
    }
}
