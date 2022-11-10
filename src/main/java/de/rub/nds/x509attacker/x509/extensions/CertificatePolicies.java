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
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
 *
 */
public class CertificatePolicies extends Asn1Sequence {

    private static final Logger LOGGER = LogManager.getLogger();

    public List<PolicyInformation> policyInformation;

    public CertificatePolicies(String identifier) {
        this.setIdentifier(identifier);
    }

    public List<PolicyInformation> getPolicyInformation() {
        return policyInformation;
    }

    public void setPolicyInformation(List<PolicyInformation> policyInformation) {
        this.policyInformation = policyInformation;
    }
}
