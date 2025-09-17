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
import de.rub.nds.x509attacker.x509.model.extensions.CertificatePolicies;
import de.rub.nds.x509attacker.x509.model.extensions.PolicyQualifiers;
import java.util.List;

public class CertificatePoliciesConfig extends ExtensionConfig {

    private List<String> policyIdentifiers;
    private List<Boolean> includeQualifiers;
    private List<PolicyQualifiers> policyQualifiers;

    public CertificatePoliciesConfig() {
        super(X509ExtensionType.CERTIFICATE_POLICIES.getOid(), "certificatePolicies");
    }

    @Override
    public CertificatePolicies getExtensionFromConfig() {
        return new CertificatePolicies("certificatePolicies");
    }

    public List<String> getPolicyIdentifiers() {
        return policyIdentifiers;
    }

    public void setPolicyIdentifiers(List<String> policyIdentifiers) {
        this.policyIdentifiers = policyIdentifiers;
    }

    public List<Boolean> getIncludeQualifiers() {
        return includeQualifiers;
    }

    public void setIncludeQualifiers(List<Boolean> includeQualifiers) {
        this.includeQualifiers = includeQualifiers;
    }

    public List<PolicyQualifiers> getPolicyQualifiers() {
        return policyQualifiers;
    }

    public void setPolicyQualifiers(List<PolicyQualifiers> policyQualifiers) {
        this.policyQualifiers = policyQualifiers;
    }
}
