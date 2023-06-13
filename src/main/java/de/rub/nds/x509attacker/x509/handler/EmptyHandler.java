package de.rub.nds.x509attacker.x509.handler;

import de.rub.nds.x509attacker.chooser.X509Chooser;

public class EmptyHandler extends X509Handler {

    public EmptyHandler(X509Chooser chooser) {
        super(chooser);
    }

    @Override
    public void adjustContext() {
        //Nothing to do
    }
    
}
