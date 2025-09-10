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
import de.rub.nds.x509attacker.config.extension.SubjectAlternativeNameConfig;
import de.rub.nds.x509attacker.x509.model.extensions.SubjectAlternativeName;
import java.util.ArrayList;
import java.util.List;

public class SubjectAlternativeNamePreparator
        extends ExtensionPreparator<SubjectAlternativeName, SubjectAlternativeNameConfig> {
    public SubjectAlternativeNamePreparator(
            X509Chooser chooser,
            SubjectAlternativeName subjectAlternativeName,
            SubjectAlternativeNameConfig config) {
        super(chooser, subjectAlternativeName, config);
    }

    @Override
    public void extensionPrepareSubComponents() {
        if (config.getGeneralNameConfigValues() != null
                && config.getGeneralNameChoiceTypeConfigs() != null) {
            field.getSubjectAltName().setGeneralNames(config.getSubjectAltName());
            field.getSubjectAltName().getPreparator(chooser).prepare();
        }
    }

    @Override
    public byte[] extensionEncodeChildrenContent() {
        List<Asn1Encodable> children = new ArrayList<>();
        children.add(field.getSubjectAltName());
        return encodeChildren(children);
    }
}
