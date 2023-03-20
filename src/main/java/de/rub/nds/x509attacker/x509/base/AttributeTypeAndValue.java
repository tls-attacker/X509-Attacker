/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.handler.EmptyHandler;
import de.rub.nds.asn1.handler.Handler;
import de.rub.nds.asn1.model.Asn1Any;
import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1PrimitiveIa5String;
import de.rub.nds.asn1.model.Asn1PrimitivePrintableString;
import de.rub.nds.asn1.model.Asn1PrimitiveT61String;
import de.rub.nds.asn1.model.Asn1PrimitiveUtf8String;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.parser.AttributeTypeAndValueParser;
import de.rub.nds.x509attacker.x509.preparator.AttributeTypeAndValuePreparator;
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
public class AttributeTypeAndValue extends Asn1Sequence<X509Chooser> {

    @HoldsModifiableVariable private Asn1ObjectIdentifier<X509Chooser> type;

    @HoldsModifiableVariable private Asn1Any<X509Chooser> value;

    private X500AttributeType attributeTypeConfig;

    private String valueConfig;

    public AttributeTypeAndValue(
            String identifier, X500AttributeType attributeTypeConfig, String valueConfig) {
        super(identifier);
        this.attributeTypeConfig = attributeTypeConfig;
        this.valueConfig = valueConfig;
        type = new Asn1ObjectIdentifier<>("type");
        value = new Asn1Any<>("value");
        addChild(type);
        addChild(value);
    }

    public AttributeTypeAndValue(String identifier) {
        super(identifier);
        type = new Asn1ObjectIdentifier<X509Chooser>("type");
        value = new Asn1Any<X509Chooser>("value");
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

    public Asn1ObjectIdentifier<X509Chooser> getType() {
        return type;
    }

    public void setType(Asn1ObjectIdentifier<X509Chooser> type) {
        this.type = type;
    }

    public Asn1Encodable<X509Chooser> getValue() {
        return value.getInstantiation();
    }

    public void instantiateValue(Asn1Field<X509Chooser> value) {
        this.value.setInstantiation(value);
    }

    @Override
    public AttributeTypeAndValuePreparator getPreparator(X509Chooser chooser) {
        return new AttributeTypeAndValuePreparator(chooser, this);
    }

    @Override
    public Asn1FieldSerializer getSerializer() {
        return super.getSerializer();
    }

    @Override
    public AttributeTypeAndValueParser getParser(X509Chooser chooser) {
        return new AttributeTypeAndValueParser(chooser, this);
    }

    @Override
    public Handler<X509Chooser> getHandler(X509Chooser chooser) {
        return new EmptyHandler<>(chooser);
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
        if (value.getInstantiation() instanceof Asn1PrimitiveIa5String) {
            builder.append(
                    ((Asn1PrimitiveIa5String<X509Chooser>) value.getInstantiation())
                            .getValue()
                            .getValue());
        } else if (value.getInstantiation() instanceof Asn1PrimitivePrintableString) {
            builder.append(
                    ((Asn1PrimitivePrintableString<X509Chooser>) value.getInstantiation())
                            .getValue()
                            .getValue());
        } else if (value.getInstantiation() instanceof Asn1PrimitiveT61String) {
            builder.append(
                    ((Asn1PrimitiveT61String<X509Chooser>) value.getInstantiation())
                            .getValue()
                            .getValue());
        } else if (value.getInstantiation() instanceof Asn1PrimitiveUtf8String) {
            builder.append(
                    ((Asn1PrimitiveUtf8String<X509Chooser>) value.getInstantiation())
                            .getValue()
                            .getValue());
        } else {
            builder.append(value.getInstantiation().toString());
        }
        return builder.toString();
    }
}
