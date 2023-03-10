/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
/**
 * KeyUsage ::= BIT STRING { digitalSignature (0), nonRepudiation (1), -- recent editions of X.509
 * have -- renamed this bit to contentCommitment keyEncipherment (2), dataEncipherment (3),
 * keyAgreement (4), keyCertSign (5), cRLSign (6), encipherOnly (7), decipherOnly (8) }
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyUsage extends Asn1PrimitiveBitString<X509Chooser> {

    private KeyUsage() {
        super(null);
    }

    public KeyUsage(String identifier) {
        super(identifier);
    }
}
