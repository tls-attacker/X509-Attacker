package de.rub.nds.x509attacker.x509.serializer.parameters;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509DssParameters;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;

public class X509DssParametersSerializer implements X509Serializer {

    public X509DssParametersSerializer(X509Chooser chooser, X509DssParameters x509DssParameters) {
    }

    @Override
    public byte[] serialize() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'serialize'");
    }

}
