/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.model.*;
import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.DirectoryStringChoiceType;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.model.AttributeTypeAndValue;
import de.rub.nds.x509attacker.x509.model.DirectoryString;
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
            Asn1PreparatorHelper.prepareField((Asn1Utf8String) valueField, value);
        } else if (valueField instanceof Asn1PrintableString) {
            Asn1PreparatorHelper.prepareField((Asn1PrintableString) valueField, value);
        } else if (valueField instanceof Asn1Ia5String) {
            Asn1PreparatorHelper.prepareField((Asn1Ia5String) valueField, value);
        } else if (valueField instanceof Asn1T61String) {
            Asn1PreparatorHelper.prepareField((Asn1T61String) valueField, value);
        } else if (valueField instanceof DirectoryString) {
            prepareDirectoryString((DirectoryString) valueField);
        } else {
            throw new UnsupportedOperationException(
                    "AttributeTypeAndValue value type not supported yet: "
                            + valueField.getClass().getSimpleName());
        }
    }

    private void prepareDirectoryString(DirectoryString directoryString) {
        if (directoryString.getSelectedChoice() instanceof Asn1Utf8String) {
            directoryString.setDirectoryStringChoiceType(DirectoryStringChoiceType.UTF8_STRING);
            directoryString.setConfigValue(
                    ((Asn1Utf8String) directoryString.getSelectedChoice()).getValue().getValue());
        } else if (directoryString.getSelectedChoice() instanceof Asn1PrintableString) {
            directoryString.setDirectoryStringChoiceType(
                    DirectoryStringChoiceType.PRINTABLE_STRING);
            directoryString.setConfigValue(
                    ((Asn1PrintableString) directoryString.getSelectedChoice())
                            .getValue()
                            .getValue());
        } else if (directoryString.getSelectedChoice() instanceof Asn1BmpString) {
            directoryString.setDirectoryStringChoiceType(DirectoryStringChoiceType.BMP_STRING);
            directoryString.setConfigValue(
                    ((Asn1BmpString) directoryString.getSelectedChoice()).getValue().getValue());
        } else if (directoryString.getSelectedChoice() instanceof Asn1UniversalString) {
            directoryString.setDirectoryStringChoiceType(
                    DirectoryStringChoiceType.UNIVERSAL_STRING);
            directoryString.setConfigValue(
                    ((Asn1UniversalString) directoryString.getSelectedChoice())
                            .getValue()
                            .getValue());
        } else {
            throw new UnsupportedOperationException(
                    "DirectoryString type not supported: "
                            + directoryString.getSelectedChoice().getClass().getSimpleName());
        }
        new DirectoryStringPreparator(this.chooser, directoryString).prepare();
    }

    private void prepareTypeConfig() {
        X500AttributeType attributeType = field.getAttributeTypeConfig();
        ObjectIdentifier oid;
        if (attributeType == null) {
            oid = new ObjectIdentifier("1.1");
        } else {
            oid = attributeType.getOid();
        }
        Asn1PreparatorHelper.prepareField(field.getType(), oid);
    }

    @Override
    public void prepareSubComponents() {
        prepareTypeConfig();
        prepareTypeValue();
    }

    @Override
    public byte[] encodeChildrenContent() {
        return encodeChildren(field.getType(), field.getValue());
    }
}
