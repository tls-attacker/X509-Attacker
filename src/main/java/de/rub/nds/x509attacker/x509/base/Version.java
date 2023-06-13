/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Explicit;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.x509attacker.constants.X509Version;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/** Version ::= INTEGER {v1(0), v2(1), v3(2) } */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Version extends Asn1Explicit {

    private Version() {
        super(null, null);
    }

    public Version(String identifier) {
        super(identifier, new Asn1Integer("value"));
    }

    public X509Version getVersion() {
        Asn1Integer asn1Integer = (Asn1Integer) getChild();
        return X509Version.convert(asn1Integer.getValue().getValue());
    }
}
