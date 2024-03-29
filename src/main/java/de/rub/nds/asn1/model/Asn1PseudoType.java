/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.asn1.model;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.serializer.Asn1PseudoTypeSerializer;
import de.rub.nds.asn1.serializer.Asn1Serializer;
import java.util.HashMap;
import java.util.Map;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAnyAttribute;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlRootElement;
import javax.xml.namespace.QName;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class Asn1PseudoType implements Asn1Encodable {

    @XmlAttribute(name = "identifier")
    private String identifier = "";

    @XmlAttribute(name = "type")
    private String type = "";

    @XmlAnyAttribute
    private Map<QName, String> attributes = new HashMap<>();

    public Asn1PseudoType() {

    }

    @Override
    public String getIdentifier() {
        return identifier;
    }

    @Override
    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    @Override
    public String getType() {
        return type;
    }

    @Override
    public void setType(String type) {
        this.type = type;
    }

    public boolean hasAttribute(final String attributeName) {
        return this.attributes.containsKey(new QName(attributeName));
    }

    public String getAttribute(final String attributeName) {
        String attribute = null;
        QName attributeQName = new QName(attributeName);
        if (this.attributes.containsKey(attributeQName)) {
            attribute = this.attributes.get(attributeQName);
        }
        return attribute;
    }

    public void setAttribute(final String attributeName, final String attributeValue) {
        this.attributes.put(new QName(attributeName), attributeValue);
    }

    public Asn1Serializer getSerializer() {
        return new Asn1PseudoTypeSerializer(this);
    }

    @Override
    public Asn1Encodable getCopy() {
        return null;
    }
}
