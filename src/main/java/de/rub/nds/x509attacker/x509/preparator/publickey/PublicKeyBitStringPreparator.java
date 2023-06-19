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
import de.rub.nds.x509attacker.x509.model.publickey.PublicKeyBitString;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PublicKeyBitStringPreparator extends Asn1FieldPreparator<PublicKeyBitString>
        implements X509Preparator {

    private static final Logger LOGGER = LogManager.getLogger();

    private final PublicKeyBitString publicKeyBitString;
    private final X509Chooser chooser;

    public PublicKeyBitStringPreparator(
            X509Chooser chooser, PublicKeyBitString publicKeyBitString) {
        super(publicKeyBitString);
        this.publicKeyBitString = publicKeyBitString;
        this.chooser = chooser;
    }

    @Override
    protected byte[] encodeContent() {
        if (publicKeyBitString.getX509PublicKeyContent() != null) {
            return encodeBitString(
                    publicKeyBitString.getX509PublicKeyContent().getSerializer(chooser).serialize(),
                    (byte) 0,
                    (byte) 0);
        } else {
            LOGGER.warn("Could not encode public key. Encoding: new byte[0] instead");
            return new byte[0];
        }
    }
}
