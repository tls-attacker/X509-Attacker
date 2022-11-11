/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 *
 * KeyPurposeId ::= OBJECT IDENTIFIER
 *
 */
public class ExtKeyUsage extends Asn1Sequence {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlElementWrapper
    @XmlElementRef
    @HoldsModifiableVariable
    private List<Asn1ObjectIdentifier> keyPurposeID;

    private ExtKeyUsage(String identifier) {
        super(identifier);
    }

    public List<Asn1ObjectIdentifier> getKeyPurposeID() {
        return keyPurposeID;
    }

    public void setKeyPurposeID(List<Asn1ObjectIdentifier> keyPurposeID) {
        this.keyPurposeID = keyPurposeID;
    }
}
