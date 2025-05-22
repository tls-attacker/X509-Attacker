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
import de.rub.nds.x509attacker.x509.model.Extension;
import de.rub.nds.x509attacker.x509.model.extensions.Unknown;

/** Config for unknown extensions or extensions with hardcoded content. */
public class UnknownConfig extends ExtensionConfig {

    private byte[] content;

    /** ObjectIdentifier has to be supplied as it cannot be inferred. */
    public UnknownConfig(ObjectIdentifier extensionId, String name) {
        super(extensionId, name);
    }

    @Override
    public Extension getExtensionFromConfig() {
        return new Unknown(name);
    }

    public byte[] getContent() {
        return content;
    }

    public void setContent(byte[] content) {
        this.content = content;
    }
}
