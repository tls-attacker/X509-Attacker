/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.extension;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.extension.UnknownConfig;
import de.rub.nds.x509attacker.x509.model.extensions.Unknown;

/** Preparator for {@link Unknown} extension. Simply sets the configured static bytes. */
public class UnknownPreparator extends ExtensionPreparator<Unknown, UnknownConfig> {

    public UnknownPreparator(X509Chooser chooser, Unknown container, UnknownConfig config) {
        super(chooser, container, config);
    }

    @Override
    public void extensionPrepareSubComponents() {
        field.setContent(config.getContent());
    }

    @Override
    public byte[] extensionEncodeChildrenContent() {
        return field.getContent().getValue();
    }
}
