/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.extension;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.extension.IssuerAlternativeNameConfig;
import de.rub.nds.x509attacker.x509.model.extensions.IssuerAlternativeName;
import java.util.ArrayList;
import java.util.List;

public class IssuerAlternativeNamePreparator
        extends ExtensionPreparator<IssuerAlternativeName, IssuerAlternativeNameConfig> {
    public IssuerAlternativeNamePreparator(
            X509Chooser chooser,
            IssuerAlternativeName container,
            IssuerAlternativeNameConfig config) {
        super(chooser, container, config);
    }

    @Override
    public void extensionPrepareSubComponents() {
        if (config.getGeneralNameConfigValues() != null
                && config.getGeneralNameChoiceTypeConfigs() != null) {
            field.getIssuerAltName().setGeneralNames(config.getIssuerAltName());
            field.getIssuerAltName().getPreparator(chooser).prepare();
        }
    }

    @Override
    public byte[] extensionEncodeChildrenContent() {
        List<Asn1Encodable> children = new ArrayList<>();
        children.add(field.getIssuerAltName());
        return encodeChildren(children);
    }
}
