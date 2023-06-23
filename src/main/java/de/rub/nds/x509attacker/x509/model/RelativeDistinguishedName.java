/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.asn1.model.Asn1Set;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.handler.RelativeDistinguishedNameHandler;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.RelativeDistinguishedNameParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.RelativeDistinguishedNamePreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.serializer.RelativeDistinguishedNameSerializer;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;

/** RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class RelativeDistinguishedName extends Asn1Set implements X509Component {

    private List<AttributeTypeAndValue> attributeTypeAndValueList;

    private RelativeDistinguishedName() {
        super(null);
    }

    public RelativeDistinguishedName(String identifier) {
        super(identifier);
    }

    public RelativeDistinguishedName(String identifier, int implicitTagNumber) {
        super(identifier, implicitTagNumber);
    }

    public RelativeDistinguishedName(
            String identifier, List<Pair<X500AttributeType, String>> attributeList) {
        super(identifier);
        attributeTypeAndValueList = new LinkedList<>();
        for (Pair<X500AttributeType, String> pair : attributeList) {
            AttributeTypeAndValue attributeTypeAndValue =
                    new AttributeTypeAndValue(
                            pair.getKey()
                                    .getHumanReadableName()
                                    .concat("=")
                                    .concat(pair.getValue()),
                            pair.getKey(),
                            pair.getValue());
            addChild(attributeTypeAndValue);
            attributeTypeAndValueList.add(attributeTypeAndValue);
        }
    }

    public RelativeDistinguishedName(
            String identifier, Pair<X500AttributeType, String>... attributes) {
        super(identifier);
        attributeTypeAndValueList = new LinkedList<>();
        for (Pair<X500AttributeType, String> pair : attributes) {
            AttributeTypeAndValue attributeTypeAndValue =
                    new AttributeTypeAndValue(
                            pair.getKey()
                                    .getHumanReadableName()
                                    .concat("=")
                                    .concat(pair.getValue()),
                            pair.getKey(),
                            pair.getValue());
            addChild(attributeTypeAndValue);
            attributeTypeAndValueList.add(attributeTypeAndValue);
        }
    }

    public List<AttributeTypeAndValue> getAttributeTypeAndValueList() {
        return attributeTypeAndValueList;
    }

    public void setAttributeTypeAndValueList(
            List<AttributeTypeAndValue> attributeTypeAndValueList) {
        this.attributeTypeAndValueList = attributeTypeAndValueList;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new RelativeDistinguishedNameHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new RelativeDistinguishedNameParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new RelativeDistinguishedNamePreparator(chooser, this);
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        return new RelativeDistinguishedNameSerializer(chooser, this);
    }
}
