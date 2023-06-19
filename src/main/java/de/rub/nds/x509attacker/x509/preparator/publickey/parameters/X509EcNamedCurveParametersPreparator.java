package de.rub.nds.x509attacker.x509.preparator.publickey.parameters;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509EcNamedCurveParameters;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;

public class X509EcNamedCurveParametersPreparator implements X509Preparator {

    public X509EcNamedCurveParametersPreparator(X509Chooser chooser,
            X509EcNamedCurveParameters x509EcNamedCurveParameters) {
    }

    @Override
    public void prepare() {
        throw new UnsupportedOperationException("Unimplemented method 'prepare'");
    }

}
