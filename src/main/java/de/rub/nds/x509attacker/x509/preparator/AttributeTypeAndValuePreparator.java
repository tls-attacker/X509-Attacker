/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.model.Asn1PrimitiveUtf8String;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.base.AttributeTypeAndValue;

public class AttributeTypeAndValuePreparator extends X509ComponentPreparator {

    private final AttributeTypeAndValue instance;

    public AttributeTypeAndValuePreparator(AttributeTypeAndValue instance, X509CertificateConfig config) {
        super(instance, config);
        this.instance = instance;
    }

    @Override
    protected byte[] encodeContent() {
        instance.getType().setValue(instance.getAttributeTypeConfig().getOid().toString());
        instance.instantiateValue(new Asn1PrimitiveUtf8String("value"));
        ((Asn1PrimitiveUtf8String) instance.getValue()).setValue(instance.getValueConfig());
        // TODO This allows more than asn1 primitive utf8 for now we only do that.
        prepareSubcomponent(instance.getType());
        prepareSubcomponent(instance.getValue());
        instance.setEncodedChildren(encodedChildren(instance.getChildren()));
        return instance.getEncodedChildren().getValue();
    }

}
