/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.AnotherName;
import de.rub.nds.x509attacker.x509.model.X509Component;
import de.rub.nds.x509attacker.x509.model.X509Explicit;
import de.rub.nds.x509attacker.x509.model.X509Utf8String;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AnotherNamePreparator extends X509ContainerPreparator<AnotherName> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AnotherNamePreparator(X509Chooser chooser, AnotherName otherName) {
        super(chooser, otherName);
    }

    @Override
    public void prepareSubComponents() {
        // Prepare the type-id (OID)
        // If the typeId already has a value, use it; otherwise use a default
        ObjectIdentifier oid;
        if (field.getTypeId().getValue() != null
                && field.getTypeId().getValue().getValue() != null) {
            oid = new ObjectIdentifier(field.getTypeId().getValue().getValue());
        } else {
            // Default OID for testing - could be any valid OID
            oid = new ObjectIdentifier("1.2.3.4");
            LOGGER.warn("AnotherName typeId not set, using default OID: 1.2.3.4");
        }
        Asn1PreparatorHelper.prepareField(field.getTypeId(), oid);

        // Prepare the value based on the configured value
        if (field.getConfiguredValue() != null) {
            // For now, we support UTF8String as the inner value
            // This can be extended to support other types based on the OID
            X509Utf8String innerValue = new X509Utf8String("innerValue");
            innerValue.setValue(field.getConfiguredValue());

            // Create a new explicit wrapper with the inner value
            X509Explicit<X509Component> explicitValue = new X509Explicit<>("value", 0, innerValue);
            field.setValue(explicitValue);

            // Prepare the explicit value using ExplicitPreparator
            ExplicitPreparator<X509Component> explicitPreparator =
                    new ExplicitPreparator<>(chooser, field.getValue());
            explicitPreparator.prepare();
        }
    }

    @Override
    public byte[] encodeChildrenContent() {
        if (field.getValue() != null && field.getValue().getInnerField() != null) {
            return encodeChildren(field.getTypeId(), field.getValue());
        } else {
            // Only encode type-id if no value is set
            return encodeChildren(field.getTypeId());
        }
    }
}
