/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.extension.ExtensionConfig;
import de.rub.nds.x509attacker.x509.model.Extension;
import de.rub.nds.x509attacker.x509.model.Extensions;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Preparator for {@link Extensions}. Delegates preparation of extensions to respective preparator
 * and adds all to extension list.
 */
public class ExtensionsPreparator extends X509ContainerPreparator<Extensions> {

    public ExtensionsPreparator(X509Chooser chooser, Extensions extensions) {
        super(chooser, extensions);
    }

    @Override
    public void prepareSubComponents() {
        // prepare all present extensions
        for (ExtensionConfig config :
                chooser.getConfig().getExtensions().stream()
                        .filter(ExtensionConfig::isPresent)
                        .collect(Collectors.toList())) {
            Extension extension = config.getExtensionFromConfig();
            extension.getPreparator(chooser, config).prepare();
            field.getExtensionList().add(extension);
        }
    }

    @Override
    public byte[] encodeChildrenContent() {
        List<Asn1Encodable> children = new ArrayList<>(field.getExtensionList());
        return encodeChildren(children);
    }
}
