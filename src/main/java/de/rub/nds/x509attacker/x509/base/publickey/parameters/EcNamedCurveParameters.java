/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.base.publickey.parameters;

import de.rub.nds.asn1.model.Asn1ObjectIdentifier;

public class EcNamedCurveParameters extends Asn1ObjectIdentifier implements PublicParameters {

    public EcNamedCurveParameters(String identifier) {
        super("namedCurve");
    }

}
