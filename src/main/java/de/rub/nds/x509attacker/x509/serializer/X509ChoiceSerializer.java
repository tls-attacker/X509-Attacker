/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.serializer;

import de.rub.nds.asn1.model.Asn1Choice;
import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X509ChoiceSerializer<Choice extends Asn1Choice> implements X509Serializer {

    @SuppressWarnings("unused")
    private final Logger LOGGER = LogManager.getLogger();

    private final Choice choice;

    /**
     * Constructs a new X509ChoiceSerializer for the given ASN.1 choice object.
     *
     * @param choice the ASN.1 choice object to serialize
     */
    public X509ChoiceSerializer(Choice choice) {
        this.choice = choice;
    }

    /** {@inheritDoc} */
    @Override
    public byte[] serialize() {
        try (SilentByteArrayOutputStream outputStream = new SilentByteArrayOutputStream()) {
            Asn1Encodable selectedChoice = choice.getSelectedChoice();
            outputStream.write(selectedChoice.getTagOctets().getValue());
            outputStream.write(selectedChoice.getLengthOctets().getValue());
            outputStream.write(selectedChoice.getContent().getValue());
            return outputStream.toByteArray();
        }
    }
}
