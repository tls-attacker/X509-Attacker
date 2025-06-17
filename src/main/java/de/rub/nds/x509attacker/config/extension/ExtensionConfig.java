/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.config.extension;

import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.x509attacker.constants.DefaultEncodingRule;
import de.rub.nds.x509attacker.x509.model.Extension;

/**
 * Abstract parent class of all Extension Configurations. Holds whether the extensions will be
 * prepared, its criticality, and OID.
 */
public abstract class ExtensionConfig {
    private final ObjectIdentifier extensionId;
    protected final String name;
    private boolean present = false;
    private boolean critical = false;

    private DefaultEncodingRule includeCritical = DefaultEncodingRule.FOLLOW_DEFAULT;

    public ExtensionConfig(ObjectIdentifier extensionId, String name) {
        this.extensionId = extensionId;
        this.name = name;
    }

    public ObjectIdentifier getExtensionId() {
        return extensionId;
    }

    public boolean isPresent() {
        return present;
    }

    public void setPresent(boolean present) {
        this.present = present;
    }

    public boolean isCritical() {
        return critical;
    }

    public void setCritical(boolean critical) {
        this.critical = critical;
    }

    public DefaultEncodingRule getIncludeCritical() {
        return includeCritical;
    }

    public void setIncludeCritical(DefaultEncodingRule includeCritical) {
        this.includeCritical = includeCritical;
    }

    public abstract Extension getExtensionFromConfig();
}
