/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * OtherName ::= SEQUENCE { type-id OBJECT IDENTIFIER, value [0] EXPLICIT ANY DEFINED BY type-id } }
 */
public class OtherName extends Asn1Sequence {

    private static final Logger LOGGER = LogManager.getLogger();

    private Asn1ObjectIdentifier type_id;
    private Asn1Encodable value;

    public OtherName(String identifier) {
        super(identifier);
    }

    public Asn1ObjectIdentifier getType_id() {
        return type_id;
    }

    public void setType_id(Asn1ObjectIdentifier type_id) {
        this.type_id = type_id;
    }

    public Asn1Encodable getValue() {
        return value;
    }

    public void setValue(Asn1Encodable value) {
        this.value = value;
    }
}
