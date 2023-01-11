/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base.publickey.parameters;

import de.rub.nds.asn1.handler.Handler;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.x509attacker.chooser.X509Chooser;

public class EcNamedCurveParameters extends Asn1ObjectIdentifier<X509Chooser>
        implements PublicParameters {

    public EcNamedCurveParameters(String identifier) {
        super("namedCurve");
    }

    @Override
    public Handler getHandler(X509Chooser chooser) {
        return super.getHandler(chooser); // Generated from
        // nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/OverriddenMethodBody
    }
}
