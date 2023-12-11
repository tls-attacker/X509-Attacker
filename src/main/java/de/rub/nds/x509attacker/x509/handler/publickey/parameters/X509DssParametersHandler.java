/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.handler.publickey.parameters;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509FieldHandler;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509DssParameters;

public class X509DssParametersHandler extends X509FieldHandler<X509DssParameters> {

    public X509DssParametersHandler(X509Chooser chooser, X509DssParameters parameters) {
        super(chooser, parameters);
    }

    @Override
    public void adjustContextAfterParse() {
        adjustContext();
    }

    @Override
    public void adjustContextAfterPrepare() {
        adjustContext();
    }

    public void adjustContext() {
        context.setSubjectDsaPrimeDivisorQ(component.getQ().getValue().getValue());
        context.setSubjectDsaPrimeModulusP(component.getP().getValue().getValue());
        context.setSubjectDsaGeneratorG(component.getG().getValue().getValue());
    }
}
