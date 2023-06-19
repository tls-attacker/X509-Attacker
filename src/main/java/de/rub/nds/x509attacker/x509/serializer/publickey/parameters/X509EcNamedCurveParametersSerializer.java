package de.rub.nds.x509attacker.x509.serializer.publickey.parameters;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509EcNamedCurveParameters;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;

public class X509EcNamedCurveParametersSerializer implements X509Serializer {

    public X509EcNamedCurveParametersSerializer(X509Chooser chooser, X509EcNamedCurveParameters x509DssParameters) {
    }

    @Override
    public byte[] serialize() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'serialize'");
    }

}
