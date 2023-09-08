/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.NameType;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.handler.NameHandler;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.NameParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.NamePreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.serializer.X509Asn1FieldSerializer;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;

/**
 * Name ::= CHOICE { -- only one possibility for now -- rdnSequence RDNSequence }
 *
 * <p>RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 * <p>We implmenet this directly as a sequenceOf instead...
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Name extends Asn1Sequence implements X509Component {

    @HoldsModifiableVariable private List<RelativeDistinguishedName> relativeDistinguishedNames;

    private NameType type;

    private Name() {
        super(null);
    }

    public Name(String identifier, NameType type) {
        super(identifier);
        this.type = type;
        relativeDistinguishedNames = new LinkedList<>();
    }

    public Name(String identifier, NameType type, int implicitTagNumber) {
        super(identifier, implicitTagNumber);
        this.type = type;
        relativeDistinguishedNames = new LinkedList<>();
    }

    public Name(
            String identifier, NameType type, List<Pair<X500AttributeType, String>> attributeList) {
        super(identifier);
        this.type = type;
        relativeDistinguishedNames = new LinkedList<>();
        for (Pair<X500AttributeType, String> attributePair : attributeList) {
            RelativeDistinguishedName relativeDistinguishedName =
                    new RelativeDistinguishedName("relativeDistinguishedName", attributePair);
            relativeDistinguishedNames.add(relativeDistinguishedName);
        }
    }

    public NameType getType() {
        return type;
    }

    public List<RelativeDistinguishedName> getRelativeDistinguishedNames() {
        return relativeDistinguishedNames;
    }

    public void setRelativeDistinguishedNames(
            List<RelativeDistinguishedName> relativeDistinguishedNames) {
        this.relativeDistinguishedNames = relativeDistinguishedNames;
    }

    public void addRelativeDistinguishedNames(RelativeDistinguishedName relativeDistinguishedName) {
        this.relativeDistinguishedNames.add(relativeDistinguishedName);
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new NameHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new NameParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new NamePreparator(chooser, this);
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        return new X509Asn1FieldSerializer(this);
    }
}
