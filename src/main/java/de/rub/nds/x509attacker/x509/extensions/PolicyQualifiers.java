/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.extensions;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import jakarta.xml.bind.annotation.XmlElementRef;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * policyQualifiers SEQUENCE SIZE (1..MAX) OF PolicyQualifierInfo OPTIONAL
 *
 */
public class PolicyQualifiers extends Asn1Sequence {

    private static final Logger LOGGER = LogManager.getLogger();

    @XmlElementWrapper
    @XmlElementRef
    @HoldsModifiableVariable
    private List<PolicyQualifierInfo> policyQualifierInfo;

    public PolicyQualifiers(String identifier) {
        super(identifier);
    }

    public List<PolicyQualifierInfo> getPolicyQualifierInfo() {
        return policyQualifierInfo;
    }

    public void setPolicyQualifierInfo(List<PolicyQualifierInfo> policyQualifierInfo) {
        this.policyQualifierInfo = policyQualifierInfo;
    }
}
