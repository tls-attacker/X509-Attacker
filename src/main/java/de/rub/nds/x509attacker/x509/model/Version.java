/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.asn1.model.Asn1Explicit;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509Version;
import de.rub.nds.x509attacker.x509.handler.VersionHandler;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.VersionParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.VersionPreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.serializer.VersionSerializer;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/** Version ::= INTEGER {v1(0), v2(1), v3(2) } */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Version extends Asn1Explicit<Asn1Integer> implements X509ExplicitComponent {

    private Version() {
        super(null, null, null);
    }

    public Version(String identifier, int exectedTagNumber) {
        super(identifier, exectedTagNumber, new Asn1Integer("value"));
    }

    public X509Version getVersion() {
        Asn1Integer asn1Integer = (Asn1Integer) getInnerField();
        return X509Version.convert(asn1Integer.getValue().getValue());
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new VersionHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new VersionParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new VersionPreparator(chooser, this);
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        return new VersionSerializer(chooser, this);
    }
}
