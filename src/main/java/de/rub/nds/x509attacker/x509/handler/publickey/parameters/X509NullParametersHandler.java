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
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509NullParameters;

public class X509NullParametersHandler extends X509FieldHandler<X509NullParameters> {

    public X509NullParametersHandler(X509Chooser chooser, X509NullParameters parameters) {
        super(chooser, parameters);
    }

    @Override
    public void adjustContext() {
        // Nothing to do
    }
}
