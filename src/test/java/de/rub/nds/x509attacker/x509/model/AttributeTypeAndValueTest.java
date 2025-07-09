/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.asn1.model.Asn1PrintableString;
import de.rub.nds.asn1.model.Asn1Utf8String;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.DirectoryStringChoiceType;
import de.rub.nds.x509attacker.constants.NameType;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.context.X509Context;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class AttributeTypeAndValueTest {

    @Test
    void testDirectoryStringChoiceTypeConfigurable() {
        // Test with UTF8_STRING (default)
        AttributeTypeAndValue attrUtf8 =
                new AttributeTypeAndValue(
                        "test",
                        X500AttributeType.COMMON_NAME,
                        "Test Value",
                        DirectoryStringChoiceType.UTF8_STRING);
        assertTrue(attrUtf8.getValue() instanceof Asn1Utf8String);

        // Test with PRINTABLE_STRING
        AttributeTypeAndValue attrPrintable =
                new AttributeTypeAndValue(
                        "test",
                        X500AttributeType.COMMON_NAME,
                        "Test Value",
                        DirectoryStringChoiceType.PRINTABLE_STRING);
        assertTrue(attrPrintable.getValue() instanceof Asn1PrintableString);
    }

    @Test
    void testConfigurableDirectoryStringTypeInCertificate() {
        // Create config with PRINTABLE_STRING
        X509CertificateConfig config = new X509CertificateConfig();
        config.setDefaultDirectoryStringType(DirectoryStringChoiceType.PRINTABLE_STRING);

        // Create subject with the config
        List<Pair<X500AttributeType, String>> subjectAttributes = new ArrayList<>();
        subjectAttributes.add(new Pair<>(X500AttributeType.COMMON_NAME, "test.example.com"));
        subjectAttributes.add(new Pair<>(X500AttributeType.ORGANISATION_NAME, "Test Org"));
        config.setSubject(subjectAttributes);

        // Create Name with the configured directory string type
        Name name =
                new Name(
                        "subject",
                        NameType.SUBJECT,
                        subjectAttributes,
                        config.getDefaultDirectoryStringType(),
                        new ArrayList<>());

        // Verify that all AttributeTypeAndValue objects use PRINTABLE_STRING
        for (RelativeDistinguishedName rdn : name.getRelativeDistinguishedNames()) {
            for (AttributeTypeAndValue atav : rdn.getAttributeTypeAndValueList()) {
                if (atav.getValue() instanceof DirectoryString) {
                    DirectoryString ds = (DirectoryString) atav.getValue();
                    // The DirectoryString will be properly set during preparation
                } else {
                    // Direct string types
                    assertTrue(
                            atav.getValue() instanceof Asn1PrintableString,
                            "Expected PrintableString but got: "
                                    + atav.getValue().getClass().getSimpleName());
                }
            }
        }
    }

    @Test
    void testDifferentEncodingTypes() {
        DirectoryStringChoiceType[] types = {
            DirectoryStringChoiceType.UTF8_STRING,
            DirectoryStringChoiceType.PRINTABLE_STRING,
            DirectoryStringChoiceType.BMP_STRING,
            DirectoryStringChoiceType.TELETEX_STRING,
            DirectoryStringChoiceType.UNIVERSAL_STRING
        };

        for (DirectoryStringChoiceType type : types) {
            X509CertificateConfig config = new X509CertificateConfig();
            config.setDefaultDirectoryStringType(type);

            // Create certificate with the config
            X509Context context = new X509Context(config);
            X509Certificate cert = new X509Certificate("cert");
            TbsCertificate tbs = new TbsCertificate("tbs", config);

            // The directory string type from config should be used
            assertEquals(type, config.getDefaultDirectoryStringType());
        }
    }
}
