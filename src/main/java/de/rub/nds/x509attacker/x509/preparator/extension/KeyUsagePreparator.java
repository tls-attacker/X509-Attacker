/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.extension;

import de.rub.nds.asn1.model.Asn1BitString;
import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.extension.KeyUsageConfig;
import de.rub.nds.x509attacker.x509.model.extensions.KeyUsage;

public class KeyUsagePreparator extends ExtensionPreparator<KeyUsage, KeyUsageConfig> {

    public KeyUsagePreparator(X509Chooser chooser, KeyUsage container, KeyUsageConfig config) {
        super(chooser, container, config);
    }

    @Override
    public void extensionPrepareSubComponents() {
        if (field.getBitString() == null) {
            field.setBitString(new Asn1BitString("bitString"));
        }
        Asn1BitString bitString = field.getBitString();
        bitString.setUnusedBits((byte) 7);
        bitString.setUsedBits(computeBitString(config));
        bitString.setPadding((byte) 0);
        bitString.setContent(
                Asn1PreparatorHelper.encodeBitString(
                        bitString.getUsedBits().getValue(),
                        bitString.getUnusedBits().getValue(),
                        bitString.getPadding().getValue()));
        Asn1PreparatorHelper.prepareAfterContent(bitString);
    }

    @Override
    public byte[] extensionEncodeChildrenContent() {
        return encodeChildren(field.getBitString());
    }

    private byte[] computeBitString(KeyUsageConfig config) {
        int lowerByte = 0;

        lowerByte |= (config.isDigitalSignature() ? 1 : 0);
        lowerByte <<= 1;

        lowerByte |= (config.isNonRepudiation() ? 1 : 0);
        lowerByte <<= 1;

        lowerByte |= (config.isKeyEncipherment() ? 1 : 0);
        lowerByte <<= 1;

        lowerByte |= (config.isDataEncipherment() ? 1 : 0);
        lowerByte <<= 1;

        lowerByte |= (config.isKeyAgreement() ? 1 : 0);
        lowerByte <<= 1;

        lowerByte |= (config.isKeyCertSign() ? 1 : 0);
        lowerByte <<= 1;

        lowerByte |= (config.iscRLSign() ? 1 : 0);
        lowerByte <<= 1;

        lowerByte |= (config.isEncipherOnly() ? 1 : 0);

        byte higherByte = (byte) (config.isDecipherOnly() ? 1 : 0);
        return new byte[] {higherByte, (byte) lowerByte};
    }
}
