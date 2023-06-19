/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.handler.publickey.parameters;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509DhParameters;
import de.rub.nds.x509attacker.x509.handler.X509Handler;

public class X509DhParametersHandler extends X509Handler {

    private final X509DhParameters parameters;

    public X509DhParametersHandler(X509Chooser chooser, X509DhParameters parameters) {
        super(chooser);
        this.parameters = parameters;
    }

    @Override
    public void adjustContext() {
        chooser.getContext().setSubjectDhGenerator(parameters.getG().getValue().getValue());
        chooser.getContext().setSubjectDhModulus(parameters.getP().getValue().getValue());
    }
}
