package de.rub.nds.x509attacker.x509.serializer.parameters;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509DhValidationParms;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;

public class X509DhValidationParmsSerializer implements X509Serializer {

    public X509DhValidationParmsSerializer(X509Chooser chooser, X509DhValidationParms x509DhValidationParms) {
    }

    @Override
    public byte[] serialize() {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'serialize'");
    }

}
