package de.rub.nds.x509attacker.x509.handler.publickey;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.PublicKeyBitString;
import de.rub.nds.x509attacker.x509.handler.X509Handler;

public class PublicKeyBitStringHandler extends X509Handler {

    public PublicKeyBitStringHandler(X509Chooser chooser, PublicKeyBitString publicKeyBitString) {
        super(chooser);
    }

    @Override
    public void adjustContext() {
        throw new UnsupportedOperationException("Unimplemented method 'adjustContext'");
    }

}
