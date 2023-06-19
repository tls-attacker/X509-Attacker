package de.rub.nds.x509attacker.x509.base.publickey.parameters;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;

public class X509DhValidationParmsPreparator implements X509Preparator {

    public X509DhValidationParmsPreparator(X509Chooser chooser, X509DhValidationParms x509DhValidationParms) {
    }

    @Override
    public void prepare() {
        throw new UnsupportedOperationException("Unimplemented method 'prepare'");
    }

}
