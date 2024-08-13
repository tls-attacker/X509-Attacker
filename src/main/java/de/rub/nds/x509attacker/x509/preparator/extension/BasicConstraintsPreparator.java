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
import de.rub.nds.x509attacker.config.extension.BasicConstraintsConfig;
import de.rub.nds.x509attacker.x509.model.extensions.BasicConstraints;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class BasicConstraintsPreparator
        extends ExtensionPreparator<BasicConstraints, BasicConstraintsConfig> {

    public BasicConstraintsPreparator(
            X509Chooser chooser, BasicConstraints container, BasicConstraintsConfig config) {
        super(chooser, container, config);
    }

    @Override
    public void extensionPrepareSubComponents() {
        field.getCa().setValue(config.isCa());
        field.getPathLenConstraint()
                .setValue(new BigInteger(String.valueOf(config.getPathLenConstraint())));
    }

    @Override
    public byte[] extensionEncodeChildrenContent() {
        List<Asn1Encodable> children = new ArrayList<>();
        if (config.isCaPresent()) {
            children.add(field.getCa());
        }
        if (config.isPathLenConstraintPresent()) {
            children.add(field.getCritical());
        }
        return encodeChildren(children);
    }
}
