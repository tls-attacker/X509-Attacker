/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.asn1.model.Asn1Sequence;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0] KeyIdentifier OPTIONAL, authorityCertIssuer [1] GeneralNames
 * OPTIONAL, authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL }
 *
 * KeyIdentifier ::= OCTET STRING
 *
 * CertificateSerialNumber ::= INTEGER
 *
 */
public class AuthorityKeyIdentifier extends Asn1Sequence {

    private static final Logger LOGGER = LogManager.getLogger();

    private Asn1PrimitiveOctetString keyIdentifier;
    private GeneralNames authorityCertIssuer;
    private Asn1Integer authorityCertSerialNumber;

    public AuthorityKeyIdentifier(String identifier) {
        this.setIdentifier(identifier);
    }

    public Asn1PrimitiveOctetString getKeyIdentifier() {
        return keyIdentifier;
    }

    public void setKeyIdentifier(Asn1PrimitiveOctetString keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
    }

    public GeneralNames getAuthorityCertIssuer() {
        return authorityCertIssuer;
    }

    public void setAuthorityCertIssuer(GeneralNames authorityCertIssuer) {
        this.authorityCertIssuer = authorityCertIssuer;
    }

    public Asn1Integer getAuthorityCertSerialNumber() {
        return authorityCertSerialNumber;
    }

    public void setAuthorityCertSerialNumber(Asn1Integer authorityCertSerialNumber) {
        this.authorityCertSerialNumber = authorityCertSerialNumber;
    }
}
