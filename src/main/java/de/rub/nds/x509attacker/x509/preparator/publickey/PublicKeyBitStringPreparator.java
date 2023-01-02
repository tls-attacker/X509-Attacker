/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.publickey;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.PublicKeyBitString;
import de.rub.nds.x509attacker.x509.preparator.X509ComponentPreparator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PublicKeyBitStringPreparator extends X509ComponentPreparator<PublicKeyBitString> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PublicKeyBitStringPreparator(
            PublicKeyBitString publicKeyBitString, X509Chooser chooser) {
        super(publicKeyBitString, chooser);
    }

    @Override
    protected byte[] encodeContent() {
        if (field.getPublicKey() != null) {
            field.getPublicKey().getPreparator(chooser).prepare();
            instance.setUnusedBits((byte) 0);
            instance.setValue(instance.getPublicKey().getSerializer().serialize());
            return instance.getValue().getValue();
        } else {
            LOGGER.warn("Could not encode public key. Encoding: new byte[0] instead");
            instance.setUnusedBits((byte) 0);
            instance.setValue(new byte[0]);
            return new byte[0];
        }
    }
}
