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
import de.rub.nds.x509attacker.x509.model.extensions.SubjectKeyIdentifier;

public class SubjectKeyIdentifierConfig extends ExtensionConfig {

    private byte[] keyIdentifier;

    public SubjectKeyIdentifierConfig() {
        super(X509ExtensionType.SUBJECT_KEY_IDENTIFIER.getOid(), "subjectKeyIdentifier");
    }

    @Override
    public SubjectKeyIdentifier getExtensionFromConfig() {
        return new SubjectKeyIdentifier("subjectKeyIdentifier");
    }

    public byte[] getKeyIdentifier() {
        return keyIdentifier;
    }

    public void setKeyIdentifier(byte[] keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
    }
}
