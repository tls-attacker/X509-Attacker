package de.rub.nds.x509attacker.x509.handler;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.EdiPartyName;

public class EdiPartyNameHandler extends X509Handler{

    public EdiPartyNameHandler(X509Chooser chooser, EdiPartyName ediPartyName) {
    }

    @Override
    public void adjustContext() {
        throw new UnsupportedOperationException("Unimplemented method 'adjustContext'");
    }

}
