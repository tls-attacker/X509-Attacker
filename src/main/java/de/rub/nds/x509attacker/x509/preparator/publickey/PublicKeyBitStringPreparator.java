/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.publickey;

import de.rub.nds.asn1.preparator.Asn1FieldPreparator;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.publickey.PublicKeyBitString;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PublicKeyBitStringPreparator
        extends Asn1FieldPreparator<X509Chooser, PublicKeyBitString> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PublicKeyBitStringPreparator(
            X509Chooser chooser, PublicKeyBitString publicKeyBitString) {
        super(chooser, publicKeyBitString);
    }

    @Override
    protected byte[] encodeContent() {
        if (field.getX509PublicKeyContent() != null) {
            field.getX509PublicKeyContent().getPreparator(chooser).prepare();
            field.setUnusedBits((byte) 0);
            field.setValue(field.getX509PublicKeyContent().getSerializer().serialize());
            return field.getValue().getValue();
        } else {
            LOGGER.warn("Could not encode public key. Encoding: new byte[0] instead");
            field.setUnusedBits((byte) 0);
            field.setValue(new byte[0]);
            return new byte[0];
        }
    }
}
