/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.handler.publickey.parameters;

import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509EcNamedCurveParameters;
import de.rub.nds.x509attacker.x509.handler.X509Handler;

public class EcNamedCurveParametersHandler extends X509Handler {

    private final X509EcNamedCurveParameters parameters;

    public EcNamedCurveParametersHandler(
            X509Chooser chooser, X509EcNamedCurveParameters parameters) {
        super(chooser);
        this.parameters = parameters;
    }

    @Override
    public void adjustContext() {
        String oid = parameters.getValue().getValue();
        X509NamedCurve namedCurve =
                X509NamedCurve.decodeFromOidBytes(new ObjectIdentifier(oid).getEncoded());
        context.setSubjectNamedCurve(namedCurve);
    }
}
