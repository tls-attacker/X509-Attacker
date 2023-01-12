/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.handler.Handler;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.Asn1SequenceParser;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.NameType;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.handler.NameHandler;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.NameParser;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;
import org.apache.commons.lang3.tuple.Pair;

/**
 * Name ::= CHOICE { -- only one possibility for now -- rdnSequence RDNSequence
 * }
 *
 * <p>
 * RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Name extends Asn1Sequence<X509Chooser> {

    @HoldsModifiableVariable
    private List<RelativeDistinguishedName> relativeDistinguishedNames;

    private NameType type;

    private Name() {
        super(null);
    }

    public Name(String identifier, NameType type) {
        super(identifier);
        this.type = type;
        relativeDistinguishedNames = new LinkedList<>();
    }

    public Name(
            String identifier, NameType type, List<Pair<X500AttributeType, String>> attributeList) {
        super(identifier);
        this.type = type;
        relativeDistinguishedNames = new LinkedList<>();
        for (Pair<X500AttributeType, String> attributePair : attributeList) {
            RelativeDistinguishedName relativeDistinguishedName
                    = new RelativeDistinguishedName("relativeDistinguishedName", attributePair);
            relativeDistinguishedNames.add(relativeDistinguishedName);
            addChild(relativeDistinguishedName);
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

    public X509Handler getSubjectNameHandler(X509Chooser chooser) {
        return new NameHandler(chooser, this);
    }

    @Override
    public Asn1SequenceParser getParser(X509Chooser chooser) {
        return new NameParser(chooser, this);
    }

    @Override
    public Handler getHandler(X509Chooser chooser) {
        return new NameHandler(chooser, this);
    }
}
