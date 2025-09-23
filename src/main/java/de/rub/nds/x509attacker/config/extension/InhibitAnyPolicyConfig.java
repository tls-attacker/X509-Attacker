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
import de.rub.nds.x509attacker.x509.model.extensions.InhibitAnyPolicy;

public class InhibitAnyPolicyConfig extends ExtensionConfig {

    private long skipCerts;

    public InhibitAnyPolicyConfig() {
        super(X509ExtensionType.INHIBIT_ANY_POLICY.getOid(), "inhibitAnyPolicy");
    }

    @Override
    public InhibitAnyPolicy getExtensionFromConfig() {
        return new InhibitAnyPolicy("inhibitAnyPolicy");
    }

    public long getSkipCerts() {
        return skipCerts;
    }

    public void setSkipCerts(long skipCerts) {
        this.skipCerts = skipCerts;
    }
}
