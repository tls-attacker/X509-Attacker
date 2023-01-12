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
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.parser.AttributeTypeAndValueParser;
import de.rub.nds.x509attacker.x509.preparator.AttributeTypeAndValuePreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * AttributeTypeAndValue ::= SEQUENCE { type AttributeType, value AttributeValue
 * }
 *
 * <p>
 * AttributeType ::= OBJECT IDENTIFIER
 *
 * <p>
 * AttributeValue ::= ANY -- DEFINED BY AttributeType
 *
 * <p>
 * DirectoryString ::= CHOICE { teletexString TeletexString (SIZE (1..MAX)),
 * printableString PrintableString (SIZE (1..MAX)), universalString
 * UniversalString (SIZE (1..MAX)), utf8String UTF8String (SIZE (1..MAX)),
 * bmpString BMPString (SIZE (1..MAX)) }
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class AttributeTypeAndValue extends Asn1Sequence<X509Chooser> {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable
    private Asn1ObjectIdentifier<X509Chooser> type;

    @HoldsModifiableVariable
    private Asn1Any<X509Chooser> value;

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
        type = new Asn1ObjectIdentifier("type");
        value = new Asn1Any("value");
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
        return value.getInstantiation();
    }

    public void instantiateValue(Asn1Field value) {
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
    public Handler getHandler(X509Chooser chooser) {
        return new EmptyHandler(chooser);
    }
}
