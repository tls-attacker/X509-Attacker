/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * AttributeTypeAndValue ::= SEQUENCE { type AttributeType, value AttributeValue }
 *
 * AttributeType ::= OBJECT IDENTIFIER
 *
 * AttributeValue ::= ANY -- DEFINED BY AttributeType
 *
 * DirectoryString ::= CHOICE { teletexString TeletexString (SIZE (1..MAX)), printableString PrintableString (SIZE
 * (1..MAX)), universalString UniversalString (SIZE (1..MAX)), utf8String UTF8String (SIZE (1..MAX)), bmpString
 * BMPString (SIZE (1..MAX)) }
 *
 *
 */
public class AttributeTypeAndValue extends Asn1Sequence {

    private static final Logger LOGGER = LogManager.getLogger();

    public Asn1ObjectIdentifier type;
    public Asn1Encodable value;

    public AttributeTypeAndValue(String identifier) {
        this.setIdentifier(identifier);
    }

    public Asn1ObjectIdentifier getType() {
        return type;
    }

    public void setType(Asn1ObjectIdentifier type) {
        this.type = type;
    }

    public Asn1Encodable getValue() {
        return value;
    }

    public void setValue(Asn1Encodable value) {
        this.value = value;
    }
}
