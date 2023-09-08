/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.publickey;

import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.publickey.PublicKeyBitString;
import de.rub.nds.x509attacker.x509.preparator.X509Asn1FieldPreparator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PublicKeyBitStringPreparator extends X509Asn1FieldPreparator<PublicKeyBitString> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PublicKeyBitStringPreparator(
            X509Chooser chooser, PublicKeyBitString publicKeyBitString) {
        super(chooser, publicKeyBitString);
    }

    @Override
    protected byte[] encodeContent() {
        if (field.getX509PublicKeyContent() != null) {
            field.getX509PublicKeyContent().getPreparator(chooser).prepare();
            return Asn1PreparatorHelper.encodeBitString(
                    field.getX509PublicKeyContent().getSerializer(chooser).serialize(),
                    (byte) 0,
                    (byte) 0);
        } else {
            LOGGER.warn("Could not encode public key. Encoding: new byte[0] instead");
            return new byte[0];
        }
    }
}
