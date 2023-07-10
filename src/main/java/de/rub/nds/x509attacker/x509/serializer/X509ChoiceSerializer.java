/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.serializer;

import de.rub.nds.asn1.model.Asn1Choice;
import de.rub.nds.asn1.model.Asn1Encodable;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X509ChoiceSerializer<Choice extends Asn1Choice> implements X509Serializer {

    @SuppressWarnings("unused")
    private final Logger LOGGER = LogManager.getLogger();

    private final Choice choice;

    public X509ChoiceSerializer(Choice choice) {
        this.choice = choice;
    }

    @Override
    public byte[] serialize() {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        Asn1Encodable selectedChoice = choice.getSelectedChoice();
        try {
            outputStream.write(selectedChoice.getTagOctets().getValue());
            outputStream.write(selectedChoice.getLengthOctets().getValue());
            outputStream.write(selectedChoice.getContent().getValue());
        } catch (IOException e) {

        }
        return outputStream.toByteArray();
    }
}
