/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.config;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.x509attacker.constants.DirectoryStringChoiceType;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.Marshaller;
import jakarta.xml.bind.Unmarshaller;
import java.io.StringReader;
import java.io.StringWriter;
import org.junit.jupiter.api.Test;

class X509CertificateConfigTest {

    @Test
    void testDefaultDirectoryStringTypeConfigurable() {
        X509CertificateConfig config = new X509CertificateConfig();

        // Test default value
        assertEquals(DirectoryStringChoiceType.UTF8_STRING, config.getDefaultDirectoryStringType());

        // Test setting different values
        config.setDefaultDirectoryStringType(DirectoryStringChoiceType.PRINTABLE_STRING);
        assertEquals(
                DirectoryStringChoiceType.PRINTABLE_STRING, config.getDefaultDirectoryStringType());

        config.setDefaultDirectoryStringType(DirectoryStringChoiceType.BMP_STRING);
        assertEquals(DirectoryStringChoiceType.BMP_STRING, config.getDefaultDirectoryStringType());

        config.setDefaultDirectoryStringType(DirectoryStringChoiceType.TELETEX_STRING);
        assertEquals(
                DirectoryStringChoiceType.TELETEX_STRING, config.getDefaultDirectoryStringType());

        config.setDefaultDirectoryStringType(DirectoryStringChoiceType.UNIVERSAL_STRING);
        assertEquals(
                DirectoryStringChoiceType.UNIVERSAL_STRING, config.getDefaultDirectoryStringType());
    }

    @Test
    void testDefaultDirectoryStringTypeXmlSerialization() throws Exception {
        // Create config with non-default value
        X509CertificateConfig originalConfig = new X509CertificateConfig();
        originalConfig.setDefaultDirectoryStringType(DirectoryStringChoiceType.PRINTABLE_STRING);

        // Serialize to XML
        JAXBContext context = JAXBContext.newInstance(X509CertificateConfig.class);
        Marshaller marshaller = context.createMarshaller();
        marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

        StringWriter writer = new StringWriter();
        marshaller.marshal(originalConfig, writer);
        String xml = writer.toString();

        // Verify XML contains the setting
        assertTrue(xml.contains("defaultDirectoryStringType"));
        assertTrue(xml.contains("PRINTABLE_STRING"));

        // Deserialize from XML
        Unmarshaller unmarshaller = context.createUnmarshaller();
        X509CertificateConfig deserializedConfig =
                (X509CertificateConfig) unmarshaller.unmarshal(new StringReader(xml));

        // Verify the value was preserved
        assertEquals(
                DirectoryStringChoiceType.PRINTABLE_STRING,
                deserializedConfig.getDefaultDirectoryStringType());
    }
}
