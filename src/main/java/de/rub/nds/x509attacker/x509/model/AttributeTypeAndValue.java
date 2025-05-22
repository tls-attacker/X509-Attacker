/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.asn1.model.*;
import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.DirectoryStringChoiceType;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.handler.EmptyHandler;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.AttributeTypeAndValueParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.AttributeTypeAndValuePreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAnyElement;
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

    @HoldsModifiableVariable
    @XmlAnyElement(lax = true)
    private Asn1Encodable value;

    private X500AttributeType attributeTypeConfig;

    private String valueConfig;

    public AttributeTypeAndValue(
            String identifier,
            X500AttributeType attributeTypeConfig,
            String valueConfig,
            DirectoryStringChoiceType choiceType) {
        super(identifier);
        this.attributeTypeConfig = attributeTypeConfig;
        this.valueConfig = valueConfig;
        type = new Asn1ObjectIdentifier("type");
        setStringType(choiceType);
    }

    public AttributeTypeAndValue(String identifier, DirectoryStringChoiceType choiceType) {
        super(identifier);
        type = new Asn1ObjectIdentifier("type");
        setStringType(choiceType);
    }

    private void setStringType(DirectoryStringChoiceType choiceType) {
        switch (choiceType) {
            case UTF8_STRING:
                value = new Asn1Utf8String("value");
                break;
            case PRINTABLE_STRING:
                value = new Asn1PrintableString("value");
                break;
            case BMP_STRING:
                value = new Asn1BmpString("value");
                break;
            case TELETEX_STRING:
                value = new Asn1T61String("value");
                break;
            case UNIVERSAL_STRING:
                value = new Asn1UniversalString("value");
        }
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

    private String getStringValueOfEncoable(Asn1Encodable tempEncodable) {
        if (tempEncodable instanceof Asn1Ia5String) {
            return ((Asn1Ia5String) tempEncodable).getValue().getValue();
        } else if (tempEncodable instanceof Asn1PrintableString) {
            return ((Asn1PrintableString) tempEncodable).getValue().getValue();
        } else if (tempEncodable instanceof Asn1T61String) {
            return ((Asn1T61String) (tempEncodable)).getValue().getValue();
        } else if (tempEncodable instanceof Asn1Utf8String) {
            return ((Asn1Utf8String) tempEncodable).getValue().getValue();
        } else if (tempEncodable instanceof DirectoryString) {
            return getStringValueOfEncoable(((DirectoryString) tempEncodable).getSelectedChoice());
        } else {
            return tempEncodable.toString();
        }
    }

    public String getStringValueOfValue() {
        return getStringValueOfEncoable(value);
    }
}
