/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model.extensions;

import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.model.GeneralName;
import de.rub.nds.x509attacker.x509.model.X509Component;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/** AccessDescription ::= SEQUENCE { accessMethod OBJECT IDENTIFIER, accessLocation GeneralName } */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class AccessDescription extends Asn1Sequence implements X509Component {

    @HoldsModifiableVariable private Asn1ObjectIdentifier accessMethod;

    @HoldsModifiableVariable private GeneralName accessLocation;

    private AccessDescription() {
        super(null);
    }

    public AccessDescription(String identifier) {
        super(identifier);
        accessMethod = new Asn1ObjectIdentifier("accessMethod");
        accessLocation = new GeneralName("accessLocation");
        addChild(accessMethod);
        addChild(accessLocation);
    }

    public Asn1ObjectIdentifier getAccessMethod() {
        return accessMethod;
    }

    public void setAccessMethod(Asn1ObjectIdentifier accessMethod) {
        this.accessMethod = accessMethod;
    }

    public GeneralName getAccessLocation() {
        return accessLocation;
    }

    public void setAccessLocation(GeneralName accessLocation) {
        this.accessLocation = accessLocation;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        throw new UnsupportedOperationException("not implemented yet");
    }
}
