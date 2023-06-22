/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.asn1.model.Asn1Choice;
import de.rub.nds.asn1.model.Asn1Ia5String;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1OctetString;
import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.NameType;
import de.rub.nds.x509attacker.x509.handler.GeneralNameHandler;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.X509ChoiceParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.GeneralNamePreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.serializer.GeneralNameSerializer;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
import jakarta.xml.bind.annotation.XmlTransient;

public class GeneralName extends Asn1Choice implements X509Component {

    @XmlTransient private final AnotherName otherName;
    @XmlTransient private final Asn1Ia5String rfc822Name;
    @XmlTransient private final Asn1Ia5String dnsName;
    @XmlTransient private final OrAddress x400Address;
    @XmlTransient private final Name directoryName;
    @XmlTransient private final EdiPartyName ediPartyName;
    @XmlTransient private final Asn1Ia5String uniformResourceIdentifier;
    @XmlTransient private final Asn1OctetString ipAddress;
    @XmlTransient private final ObjectIdentifier registeredId;

    public GeneralName(String identifier) {
        super(
                identifier,
                new AnotherName("otherName", 0),
                new Asn1Ia5String("rfc822Name", 1),
                new Asn1Ia5String("dNSName", 2),
                new OrAddress("x400Address", 3),
                new Name("directoryName", NameType.GENERAL_NAME, 4),
                new EdiPartyName("ediPartyName", 5),
                new Asn1Ia5String("uniformResourceIdentifier", 6),
                new Asn1OctetString("iPAddress", 7),
                new Asn1ObjectIdentifier("registeredID", 8));
        otherName = (AnotherName) getSelecteableEncodables().get(0);
        rfc822Name = (Asn1Ia5String) getSelecteableEncodables().get(1);
        dnsName = (Asn1Ia5String) getSelecteableEncodables().get(2);
        x400Address = (OrAddress) getSelecteableEncodables().get(3);
        directoryName = (Name) getSelecteableEncodables().get(4);
        ediPartyName = (EdiPartyName) getSelecteableEncodables().get(5);
        uniformResourceIdentifier = (Asn1Ia5String) getSelecteableEncodables().get(6);
        ipAddress = (Asn1OctetString) getSelecteableEncodables().get(7);
        registeredId = (ObjectIdentifier) getSelecteableEncodables().get(8);
    }

    @SuppressWarnings("unused")
    private GeneralName() {
        this("generalName");
    }

    public AnotherName getOtherName() {
        return otherName;
    }

    public Asn1Ia5String getRfc822Name() {
        return rfc822Name;
    }

    public Asn1Ia5String getDnsName() {
        return dnsName;
    }

    public OrAddress getX400Address() {
        return x400Address;
    }

    public Name getDirectoryName() {
        return directoryName;
    }

    public EdiPartyName getEdiPartyName() {
        return ediPartyName;
    }

    public Asn1Ia5String getUniformResourceIdentifier() {
        return uniformResourceIdentifier;
    }

    public Asn1OctetString getIpAddress() {
        return ipAddress;
    }

    public ObjectIdentifier getRegisteredId() {
        return registeredId;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new GeneralNameHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new X509ChoiceParser(chooser, this);
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        return new GeneralNameSerializer(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new GeneralNamePreparator(chooser, this);
    }
}
