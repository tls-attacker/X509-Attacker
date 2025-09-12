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
import de.rub.nds.x509attacker.x509.model.extensions.PolicyConstraints;

public class PolicyConstraintsConfig extends ExtensionConfig {

    private long skipCertsRequired;
    private long skipCertsInhibit;

    private boolean includeRequired;
    private boolean includeInhibit;

    public PolicyConstraintsConfig() {
        super(X509ExtensionType.POLICY_CONSTRAINTS.getOid(), "policyConstraints");
    }

    @Override
    public PolicyConstraints getExtensionFromConfig() {
        return new PolicyConstraints("policyConstraints");
    }

    public long getSkipCertsRequired() {
        return skipCertsRequired;
    }

    public void setSkipCertsRequired(long skipCertsRequired) {
        this.skipCertsRequired = skipCertsRequired;
    }

    public long getSkipCertsInhibit() {
        return skipCertsInhibit;
    }

    public void setSkipCertsInhibit(long skipCertsInhibit) {
        this.skipCertsInhibit = skipCertsInhibit;
    }

    public boolean isIncludeRequired() {
        return includeRequired;
    }

    public void setIncludeRequired(boolean includeRequired) {
        this.includeRequired = includeRequired;
    }

    public boolean isIncludeInhibit() {
        return includeInhibit;
    }

    public void setIncludeInhibit(boolean includeInhibit) {
        this.includeInhibit = includeInhibit;
    }
}
