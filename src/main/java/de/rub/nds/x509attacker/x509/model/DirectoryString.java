/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.asn1.model.Asn1BmpString;
import de.rub.nds.asn1.model.Asn1Choice;
import de.rub.nds.asn1.model.Asn1PrintableString;
import de.rub.nds.asn1.model.Asn1T61String;
import de.rub.nds.asn1.model.Asn1UniversalString;
import de.rub.nds.asn1.model.Asn1Utf8String;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.DirectoryStringChoiceType;
import de.rub.nds.x509attacker.x509.handler.DirectoryStringHandler;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.X509ChoiceParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.DirectoryStringPreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.serializer.DirectoryStringSerializer;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlTransient;

/**
 * // @formatter:off DirectoryString ::= CHOICE { teletexString TeletexString (SIZE (1..MAX)),
 * printableString PrintableString (SIZE (1..MAX)), universalString UniversalString (SIZE (1..MAX)),
 * utf8String UTF8String (SIZE (1..MAX)), bmpString BMPString (SIZE (1..MAX)) } // @formatter:on
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class DirectoryString extends Asn1Choice implements X509Component {

    @XmlTransient private Asn1T61String teletexString;
    @XmlTransient private Asn1PrintableString printableString;
    @XmlTransient private Asn1UniversalString universalString;
    @XmlTransient private Asn1Utf8String utf8String;
    @XmlTransient private Asn1BmpString bmpString;

    private DirectoryStringChoiceType directoryStringChoiceType;

    private String configValue;

    private DirectoryString() {
        super(
                "directoryString",
                new Asn1T61String("TeletexString", 0),
                new Asn1PrintableString("PrintableString", 1),
                new Asn1UniversalString("UniversalString", 2),
                new Asn1Utf8String("UTF8String", 3),
                new Asn1BmpString("BMPString", 4));
        teletexString = (Asn1T61String) getSelecteableEncodables().get(0);
        printableString = (Asn1PrintableString) getSelecteableEncodables().get(1);
        universalString = (Asn1UniversalString) getSelecteableEncodables().get(2);
        utf8String = (Asn1Utf8String) getSelecteableEncodables().get(3);
        bmpString = (Asn1BmpString) getSelecteableEncodables().get(4);
    }

    public DirectoryString(String identifier) {
        this();
        this.setIdentifier(identifier);
    }

    public DirectoryString(String identifier, int implicitTagNumber) {
        this();
    }

    public DirectoryStringChoiceType getDirectoryStringChoiceType() {
        return directoryStringChoiceType;
    }

    public void setDirectoryStringChoiceType(DirectoryStringChoiceType directoryStringChoiceType) {
        this.directoryStringChoiceType = directoryStringChoiceType;
    }

    public String getConfigValue() {
        return configValue;
    }

    public void setConfigValue(String configValue) {
        this.configValue = configValue;
    }

    public Asn1T61String getTeletexString() {
        return teletexString;
    }

    public Asn1PrintableString getPrintableString() {
        return printableString;
    }

    public Asn1UniversalString getUniversalString() {
        return universalString;
    }

    public Asn1Utf8String getUtf8String() {
        return utf8String;
    }

    public Asn1BmpString getBmpString() {
        return bmpString;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new DirectoryStringHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new X509ChoiceParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new DirectoryStringPreparator(chooser, this);
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        return new DirectoryStringSerializer(chooser, this);
    }
}
