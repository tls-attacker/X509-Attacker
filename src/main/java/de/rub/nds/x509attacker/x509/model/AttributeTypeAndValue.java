/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Ia5String;
import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrintableString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.model.Asn1T61String;
import de.rub.nds.asn1.model.Asn1Utf8String;
import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.handler.EmptyHandler;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.AttributeTypeAndValueParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.AttributeTypeAndValuePreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.serializer.X509Asn1FieldSerializer;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * AttributeTypeAndValue ::= SEQUENCE { type AttributeType, value AttributeValue }
 *
 * <p>AttributeType ::= OBJECT IDENTIFIER
 *
 * <p>AttributeValue ::= ANY -- DEFINED BY AttributeType
 *
 * <p>DirectoryString ::= CHOICE { teletexString TeletexString (SIZE (1..MAX)), printableString
 * PrintableString (SIZE (1..MAX)), universalString UniversalString (SIZE (1..MAX)), utf8String
 * UTF8String (SIZE (1..MAX)), bmpString BMPString (SIZE (1..MAX)) }
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class AttributeTypeAndValue extends Asn1Sequence implements X509Component {

    @HoldsModifiableVariable private Asn1ObjectIdentifier type;

    @HoldsModifiableVariable private Asn1Encodable value;

    private X500AttributeType attributeTypeConfig;

    private String valueConfig;

    public AttributeTypeAndValue(
            String identifier, X500AttributeType attributeTypeConfig, String valueConfig) {
        super(identifier);
        this.attributeTypeConfig = attributeTypeConfig;
        this.valueConfig = valueConfig;
        type = new Asn1ObjectIdentifier("type");
        value = new Asn1Null("value");
        addChild(type);
        addChild(value);
    }

    public AttributeTypeAndValue(String identifier) {
        super(identifier);
        type = new Asn1ObjectIdentifier("type");
        value = new Asn1Null("value");
        addChild(type);
        addChild(value);
    }

    private AttributeTypeAndValue() {
        super(null);
    }

    public X500AttributeType getAttributeTypeConfig() {
        return attributeTypeConfig;
    }

    public void setAttributeTypeConfig(X500AttributeType attributeTypeConfig) {
        this.attributeTypeConfig = attributeTypeConfig;
    }

    public String getValueConfig() {
        return valueConfig;
    }

    public void setValueConfig(String valueConfig) {
        this.valueConfig = valueConfig;
    }

    public Asn1ObjectIdentifier getType() {
        return type;
    }

    public void setType(Asn1ObjectIdentifier type) {
        this.type = type;
    }

    public Asn1Encodable getValue() {
        return value;
    }

    public void setValue(Asn1Encodable value) {
        this.value = value;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new EmptyHandler<AttributeTypeAndValue>(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new AttributeTypeAndValueParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new AttributeTypeAndValuePreparator(chooser, this);
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        return new X509Asn1FieldSerializer(this);
    }

    public String getStringRepresentation() {
        StringBuilder builder = new StringBuilder();
        ObjectIdentifier oid = new ObjectIdentifier(getType().getValue().getValue());
        X500AttributeType x500AttributeType =
                X500AttributeType.decodeFromOidBytes(oid.getEncoded());
        if (x500AttributeType != null) {
            builder.append(x500AttributeType.getShortString());
        } else {
            builder.append(oid.toString());
        }
        builder.append("=");
        builder.append(getStringValueOfValue());
        return builder.toString();
    }

    public X500AttributeType getX500AttributeTypeFromValue() {
        ObjectIdentifier oid = new ObjectIdentifier(getType().getValue().getValue());
        return X500AttributeType.decodeFromOidBytes(oid.getEncoded());
    }

    public String getStringValueOfValue() {
        if (value instanceof Asn1Ia5String) {
            return ((Asn1Ia5String) value).getValue().getValue();
        } else if (value instanceof Asn1PrintableString) {
            return ((Asn1PrintableString) value).getValue().getValue();
        } else if (value instanceof Asn1T61String) {
            return ((Asn1T61String) (value)).getValue().getValue();
        } else if (value instanceof Asn1Utf8String) {
            return ((Asn1Utf8String) value).getValue().getValue();
        } else {
            return value.toString();
        }
    }
}
