/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.asn1.constants.UniversalTagNumber;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.AnotherNameHandler;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.AnotherNameParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.AnotherNamePreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * OtherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY DEFINED BY type-id } }
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class AnotherName extends Asn1Sequence implements X509Component {

    @HoldsModifiableVariable private Asn1ObjectIdentifier typeId;

    @HoldsModifiableVariable private X509Explicit<X509Component> value;

    private String configuredValue;

    private AnotherName() {
        super(null);
    }

    public AnotherName(String identifier) {
        this(identifier, UniversalTagNumber.SEQUENCE.getIntValue());
    }

    public AnotherName(String identifier, Integer tagNumber) {
        super(identifier, tagNumber);
        typeId = new Asn1ObjectIdentifier("typeId");
        // What the inner field is will be determined by the type-id
        // right now it is null, preparator or parse might overwrite this.
        // TODO Ideally we would have the value preset from the config
        value = new X509Explicit<>("", 0, null);
    }

    public Asn1ObjectIdentifier getTypeId() {
        return typeId;
    }

    public void setTypeId(Asn1ObjectIdentifier typeId) {
        this.typeId = typeId;
    }

    public X509Explicit<X509Component> getValue() {
        return value;
    }

    public void setValue(X509Explicit<X509Component> value) {
        this.value = value;
    }

    public String getConfiguredValue() {
        return configuredValue;
    }

    public void setConfiguredValue(String configuredValue) {
        this.configuredValue = configuredValue;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new AnotherNameHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new AnotherNameParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new AnotherNamePreparator(chooser, this);
    }
}
