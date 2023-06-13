/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.model.Asn1Utf8String;
import de.rub.nds.asn1.preparator.Asn1SequencePreparator;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.AttributeTypeAndValue;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class AttributeTypeAndValuePreparator extends Asn1SequencePreparator
        implements X509Preparator {
    private static final Logger LOGGER = LogManager.getLogger();

    private final AttributeTypeAndValue instance;

    public AttributeTypeAndValuePreparator(X509Chooser chooser, AttributeTypeAndValue instance) {
        super(chooser, instance);
        this.instance = instance;
    }

    @Override
    protected byte[] encodeContent() {
        prepareTypeConfig();
        prepareTypeValue();
        instance.setEncodedChildren(encodedChildren(instance.getChildren()));
        return instance.getEncodedChildren().getValue();
    }

    public void prepareTypeValue() {
        instance.instantiateValue(new Asn1Utf8String<>("value"));
        if (instance.getValueConfig() != null) {
            ((Asn1Utf8String) instance.getValue()).setValue(instance.getValueConfig());
        } else {
            LOGGER.warn("AttributeTypeAndValue value config is not set - using an empty string");
            ((Asn1Utf8String) instance.getValue()).setValue("");
        }
        instance.getValue().getPreparator(chooser).prepare();
    }

    private void prepareTypeConfig() {
        if (instance.getAttributeTypeConfig() != null) {
            instance.getType().setValue(instance.getAttributeTypeConfig().getOid().toString());
        } else {
            LOGGER.warn("AttributeTypeAndValue type config is not set - Using OID 1.1");
            instance.getType().setValue("1.1");
        }
        instance.getType().getPreparator(chooser).prepare();
    }
}
