/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Ia5String;
import de.rub.nds.asn1.model.Asn1PrintableString;
import de.rub.nds.asn1.model.Asn1T61String;
import de.rub.nds.asn1.model.Asn1Utf8String;
import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.model.AttributeTypeAndValue;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AttributeTypeAndValuePreparator
        extends X509ContainerPreparator<AttributeTypeAndValue> {

    private static final Logger LOGGER = LogManager.getLogger();

    public AttributeTypeAndValuePreparator(
            X509Chooser chooser, AttributeTypeAndValue attributeTypeAndValue) {
        super(chooser, attributeTypeAndValue);
    }

    public void prepareTypeValue() {
        Asn1Encodable valueField = field.getValue();
        String value = field.getValueConfig();
        if (value == null) {
            LOGGER.warn(
                    "AttributeTypeAndValue value config is not set - using an empty string \"\"");
            value = "";
        }
        if (valueField instanceof Asn1Utf8String) {
            prepareField((Asn1Utf8String) valueField, value);
        }
        if (valueField instanceof Asn1PrintableString) {
            prepareField((Asn1PrintableString) valueField, value);
        }
        if (valueField instanceof Asn1Ia5String) {
            prepareField((Asn1Ia5String) valueField, value);
        }
        if (valueField instanceof Asn1T61String) {
            prepareField((Asn1T61String) valueField, value);
        }
    }

    private void prepareTypeConfig() {
        X500AttributeType attributeType = field.getAttributeTypeConfig();
        ObjectIdentifier oid;
        if (attributeType == null) {
            oid = new ObjectIdentifier("1.1");
        } else {
            oid = attributeType.getOid();
        }
        prepareField(field.getType(), oid);
    }

    @Override
    public void prepareSubComponents() {
        prepareTypeConfig();
        prepareTypeValue();
    }
}
