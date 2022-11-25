/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Any;
import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.Asn1FieldParser;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.parser.AttributeTypeAndValueParser;
import de.rub.nds.x509attacker.x509.preparator.AttributeTypeAndValuePreparator;
import de.rub.nds.x509attacker.x509.preparator.X509ComponentPreparator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
public class AttributeTypeAndValue extends Asn1Sequence implements X509Component {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable private Asn1ObjectIdentifier type;

    @HoldsModifiableVariable private Asn1Any value;

    private X500AttributeType attributeTypeConfig;

    private String valueConfig;

    public AttributeTypeAndValue(
            String identifier, X500AttributeType attributeTypeConfig, String valueConfig) {
        super(identifier);
        this.attributeTypeConfig = attributeTypeConfig;
        this.valueConfig = valueConfig;
        type = new Asn1ObjectIdentifier("type");
        value = new Asn1Any("value");
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
    public X509ComponentPreparator getPreparator(X509Chooser chooser) {
        return new AttributeTypeAndValuePreparator(this, chooser);
    }

    @Override
    public Asn1FieldSerializer getSerializer() {
        return super.getGenericSerializer();
    }

    @Override
    public Asn1FieldParser<Asn1Sequence> getParser() {
        return new AttributeTypeAndValueParser(this);
    }
}
