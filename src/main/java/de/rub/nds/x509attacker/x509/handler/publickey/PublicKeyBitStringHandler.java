/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.handler.publickey;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509FieldHandler;
import de.rub.nds.x509attacker.x509.model.publickey.PublicKeyBitString;

public class PublicKeyBitStringHandler extends X509FieldHandler<PublicKeyBitString> {

    public PublicKeyBitStringHandler(X509Chooser chooser, PublicKeyBitString publicKeyBitString) {
        super(chooser, publicKeyBitString);
    }

    @Override
    public void adjustContextAfterParse() {
        // Nothing to do
    }

    @Override
    public void adjustContextAfterPrepare() {
        // Nothing to do
    }

    public void adjustContext() {
        component.getX509PublicKeyContent().adjustInContext(chooser);
    }
}
