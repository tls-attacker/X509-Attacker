package de.rub.nds.x509attacker.x509.base.publickey.parameters;

import de.rub.nds.asn1.model.Asn1ObjectIdentifier;

public class EcNamedCurveParameters extends Asn1ObjectIdentifier {

    public EcNamedCurveParameters(String identifier) {
        super("namedCurve");
    }

}
