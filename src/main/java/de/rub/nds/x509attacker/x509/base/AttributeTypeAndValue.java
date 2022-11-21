/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
import de.rub.nds.asn1.preparator.Preparator;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * AttributeTypeAndValue ::= SEQUENCE { type AttributeType, value AttributeValue }
 *
 * AttributeType ::= OBJECT IDENTIFIER
 *
 * AttributeValue ::= ANY -- DEFINED BY AttributeType
 *
 * DirectoryString ::= CHOICE { teletexString TeletexString (SIZE (1..MAX)), printableString PrintableString (SIZE
 * (1..MAX)), universalString UniversalString (SIZE (1..MAX)), utf8String UTF8String (SIZE (1..MAX)), bmpString
 * BMPString (SIZE (1..MAX)) }
 *
 *
 */
public class AttributeTypeAndValue extends Asn1Sequence {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable
    private Asn1ObjectIdentifier type;

    @HoldsModifiableVariable
    private Asn1Any value;

    private X500AttributeType attributeTypeConfig;

    private String valueConfig;

    public AttributeTypeAndValue(String identifier, X500AttributeType attributeTypeConfig, String valueConfig) {
        super(identifier);
        this.attributeTypeConfig = attributeTypeConfig;
        this.valueConfig = valueConfig;
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
        return value;
    }

    public void instantiateValue(Asn1Field value) {
        this.value.setInstantiation(value);
    }

    @Override
    public Preparator getGenericPreparator() {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from
                                                                       // nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

}
