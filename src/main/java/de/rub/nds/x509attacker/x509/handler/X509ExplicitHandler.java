package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;

public class X509ExplicitHandler extends X509Handler {

    public X509ExplicitHandler(X509Chooser chooser, ExplicitExtensions explicitExtensions) {
    }

    @Override
    public void adjustContext() {
        throw new UnsupportedOperationException("Unimplemented method 'adjustContext'");
    }

}
