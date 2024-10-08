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
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.x509.handler.X509FieldHandler;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509EcNamedCurveParameters;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X509EcNamedCurveParametersHandler
        extends X509FieldHandler<X509EcNamedCurveParameters> {

    private static final Logger LOGGER = LogManager.getLogger();

    public X509EcNamedCurveParametersHandler(
            X509Chooser chooser, X509EcNamedCurveParameters parameters) {
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
        X509NamedCurve namedCurve =
                X509NamedCurve.decodeFromOidBytes(component.getValueAsOid().getEncoded());
        if (namedCurve == null) {
            LOGGER.warn("X509NamedCurve with OID: {} not recognized.", component.getValueAsOid());
        }
        LOGGER.debug("Parameters with named curve: {}", namedCurve);
        context.setSubjectNamedCurve(namedCurve);
    }
}
