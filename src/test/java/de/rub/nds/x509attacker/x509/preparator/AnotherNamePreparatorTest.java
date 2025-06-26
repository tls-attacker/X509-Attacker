/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.model.AnotherName;
import de.rub.nds.x509attacker.x509.model.X509Component;
import de.rub.nds.x509attacker.x509.model.X509Explicit;
import de.rub.nds.x509attacker.x509.model.X509Utf8String;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class AnotherNamePreparatorTest {

    private X509Context context;
    private X509Chooser chooser;

    @BeforeEach
    public void setUp() {
        context = new X509Context();
        chooser = context.getChooser();
    }

    @Test
    public void testPrepareWithConfiguredValue() {
        // Create AnotherName with configured value
        AnotherName anotherName = new AnotherName("anotherName");
        anotherName.setConfiguredValue("test value");

        // Set OID
        anotherName.getTypeId().setValue("1.2.3.4.5");

        // Prepare
        AnotherNamePreparator preparator = new AnotherNamePreparator(chooser, anotherName);
        preparator.prepare();

        // Verify type-id is prepared
        Assertions.assertNotNull(anotherName.getTypeId().getValue());
        Assertions.assertEquals("1.2.3.4.5", anotherName.getTypeId().getValue().getValue());

        // Verify value is prepared
        Assertions.assertNotNull(anotherName.getValue());
        X509Explicit<X509Component> explicitValue = anotherName.getValue();
        Assertions.assertNotNull(explicitValue.getInnerField());
        Assertions.assertTrue(explicitValue.getInnerField() instanceof X509Utf8String);

        // Verify content
        X509Utf8String innerValue = (X509Utf8String) explicitValue.getInnerField();
        Assertions.assertEquals("test value", innerValue.getValue().getValue());
    }

    @Test
    public void testPrepareWithoutConfiguredValue() {
        // Create AnotherName without configured value
        AnotherName anotherName = new AnotherName("anotherName");

        // Prepare
        AnotherNamePreparator preparator = new AnotherNamePreparator(chooser, anotherName);
        preparator.prepare();

        // Verify type-id is prepared with default
        Assertions.assertNotNull(anotherName.getTypeId().getValue());
        Assertions.assertEquals("1.2.3.4", anotherName.getTypeId().getValue().getValue());

        // Verify value remains null
        Assertions.assertNotNull(anotherName.getValue());
        Assertions.assertNull(anotherName.getValue().getInnerField());
    }

    @Test
    public void testEncodingWithConfiguredValue() {
        // Create AnotherName with configured value
        AnotherName anotherName = new AnotherName("anotherName");
        anotherName.setConfiguredValue("encoded test");
        anotherName.getTypeId().setValue("2.5.4.3");

        // Prepare
        AnotherNamePreparator preparator = new AnotherNamePreparator(chooser, anotherName);
        preparator.prepare();

        // Test encoding
        byte[] encoded = anotherName.getSerializer(chooser).serialize();
        Assertions.assertNotNull(encoded);
        Assertions.assertTrue(encoded.length > 0);
    }
}
