/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.config.extension;

import de.rub.nds.x509attacker.constants.X509ExtensionType;
import de.rub.nds.x509attacker.x509.model.extensions.PolicyMappings;
import java.util.List;

public class PolicyMappingsConfig extends ExtensionConfig {

    private List<String> issuerDomainPolicies;
    private List<String> subjectDomainPolicies;

    public PolicyMappingsConfig() {
        super(X509ExtensionType.POLICY_MAPPINGS.getOid(), "policyMappings");
    }

    @Override
    public PolicyMappings getExtensionFromConfig() {
        return new PolicyMappings("policyMappings");
    }

    public List<String> getIssuerDomainPolicies() {
        return issuerDomainPolicies;
    }

    public void setIssuerDomainPolicies(List<String> issuerDomainPolicies) {
        this.issuerDomainPolicies = issuerDomainPolicies;
    }

    public List<String> getSubjectDomainPolicies() {
        return subjectDomainPolicies;
    }

    public void setSubjectDomainPolicies(List<String> subjectDomainPolicies) {
        this.subjectDomainPolicies = subjectDomainPolicies;
    }
}
