/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * SubjectKeyIdentifier ::= KeyIdentifier
 *
 * <p>KeyIdentifier ::= OCTET STRING
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SubjectKeyIdentifier extends Asn1PrimitiveOctetString<X509Chooser> {

    private SubjectKeyIdentifier() {
        super(null);
    }

    private SubjectKeyIdentifier(String identifier) {
        super(identifier);
    }
}
