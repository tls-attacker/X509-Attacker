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
import org.junit.jupiter.api.Test;

class X509CertificateConfigTest {

    @Test
    void testDefaultDirectoryStringTypeIsConfigurable() {
        X509CertificateConfig config = new X509CertificateConfig();

        // Test that default value is UTF8_STRING when not explicitly set
        assertEquals(DirectoryStringChoiceType.UTF8_STRING, config.getDefaultDirectoryStringType());

        // Test that it can be changed to PRINTABLE_STRING
        config.setDefaultDirectoryStringType(DirectoryStringChoiceType.PRINTABLE_STRING);
        assertEquals(
                DirectoryStringChoiceType.PRINTABLE_STRING, config.getDefaultDirectoryStringType());

        // Test that it can be changed to BMP_STRING
        config.setDefaultDirectoryStringType(DirectoryStringChoiceType.BMP_STRING);
        assertEquals(DirectoryStringChoiceType.BMP_STRING, config.getDefaultDirectoryStringType());

        // Test that it can be changed to TELETEX_STRING
        config.setDefaultDirectoryStringType(DirectoryStringChoiceType.TELETEX_STRING);
        assertEquals(
                DirectoryStringChoiceType.TELETEX_STRING, config.getDefaultDirectoryStringType());

        // Test that it can be changed to UNIVERSAL_STRING
        config.setDefaultDirectoryStringType(DirectoryStringChoiceType.UNIVERSAL_STRING);
        assertEquals(
                DirectoryStringChoiceType.UNIVERSAL_STRING, config.getDefaultDirectoryStringType());

        // Test that it can be set to null and still returns UTF8_STRING as default
        config.setDefaultDirectoryStringType(null);
        assertEquals(DirectoryStringChoiceType.UTF8_STRING, config.getDefaultDirectoryStringType());
    }
}
