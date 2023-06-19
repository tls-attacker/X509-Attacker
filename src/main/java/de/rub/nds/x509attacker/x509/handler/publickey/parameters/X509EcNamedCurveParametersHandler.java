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
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.x509.handler.X509FieldHandler;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509EcNamedCurveParameters;

public class X509EcNamedCurveParametersHandler
        extends X509FieldHandler<X509EcNamedCurveParameters> {

    public X509EcNamedCurveParametersHandler(
            X509Chooser chooser, X509EcNamedCurveParameters parameters) {
        super(chooser, parameters);
    }

    @Override
    public void adjustContext() {
        X509NamedCurve namedCurve =
                X509NamedCurve.decodeFromOidBytes(component.getValueAsOid().getEncoded());
        context.setSubjectNamedCurve(namedCurve);
    }
}
