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
import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * OtherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY DEFINED BY type-id } }
 */
public class OtherName extends Asn1Sequence<X509Chooser> {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable private Asn1ObjectIdentifier typeId;

    @HoldsModifiableVariable private Asn1Encodable value;

    public OtherName(String identifier) {
        super(identifier);
        typeId = new Asn1ObjectIdentifier("typeId");
        value = new Asn1Null("value");
        addChild(typeId);
        addChild(value);
    }

    public Asn1ObjectIdentifier getTypeId() {
        return typeId;
    }

    public void setTypeId(Asn1ObjectIdentifier typeId) {
        this.typeId = typeId;
    }

    public Asn1Encodable getValue() {
        return value;
    }

    public void setValue(Asn1Encodable value) {
        this.value = value;
    }

    @Override
    public Handler getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
