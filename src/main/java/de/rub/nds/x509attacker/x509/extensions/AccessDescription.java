/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.handler.Handler;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** AccessDescription ::= SEQUENCE { accessMethod OBJECT IDENTIFIER, accessLocation GeneralName } */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class AccessDescription extends Asn1Sequence<X509Chooser> {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable private Asn1ObjectIdentifier<X509Chooser> accessMethod;

    @HoldsModifiableVariable private GeneralName accessLocation;

    private AccessDescription() {
        super(null);
    }

    public AccessDescription(String identifier) {
        super(identifier);
        accessMethod = new Asn1ObjectIdentifier<>("accessMethod");
        accessLocation = new GeneralName("accessLocation");
        addChild(accessMethod);
        addChild(accessLocation);
    }

    public Asn1ObjectIdentifier<X509Chooser> getAccessMethod() {
        return accessMethod;
    }

    public void setAccessMethod(Asn1ObjectIdentifier<X509Chooser> accessMethod) {
        this.accessMethod = accessMethod;
    }

    public GeneralName getAccessLocation() {
        return accessLocation;
    }

    public void setAccessLocation(GeneralName accessLocation) {
        this.accessLocation = accessLocation;
    }

    @Override
    public Handler<X509Chooser> getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
