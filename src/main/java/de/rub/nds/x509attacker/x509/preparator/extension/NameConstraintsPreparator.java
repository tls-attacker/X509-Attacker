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
import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.extension.NameConstraintsConfig;
import de.rub.nds.x509attacker.x509.model.extensions.NameConstraints;
import java.util.ArrayList;
import java.util.List;

public class NameConstraintsPreparator
        extends ExtensionPreparator<NameConstraints, NameConstraintsConfig> {
    public NameConstraintsPreparator(
            X509Chooser chooser, NameConstraints container, NameConstraintsConfig config) {
        super(chooser, container, config);
    }

    @Override
    public void extensionPrepareSubComponents() {
        // TODO: Probably refactor into Asn1 classes that hold context-specific tags

        if (config.getPermittedSubtrees() != null) {
            field.setPermittedSubtrees(config.getPermittedSubtrees());
            field.getPermittedSubtrees().getPreparator(chooser).prepare();

            // set context-specific tag
            field.getPermittedSubtrees().setTagOctets(new byte[] {(byte) 0xa0});

            // set outer length
            field.getPermittedSubtrees()
                    .setLengthOctets(
                            new byte[] {
                                (byte) (field.getPermittedSubtrees().getContent().getValue().length)
                            });
        }

        if (config.getExcludedSubtrees() != null) {
            field.setExcludedSubtrees(config.getExcludedSubtrees());
            field.getExcludedSubtrees().getPreparator(chooser).prepare();

            // set context-specific tag
            field.getExcludedSubtrees().setTagOctets(new byte[] {(byte) 0xa1});

            // set outer length
            field.getExcludedSubtrees()
                    .setLengthOctets(
                            new byte[] {
                                (byte) (field.getExcludedSubtrees().getContent().getValue().length)
                            });
        }

        field.getWrappingSequence().setContent(encodeSequenceContent());
        Asn1PreparatorHelper.prepareAfterContent(field.getWrappingSequence());
    }

    @Override
    public byte[] extensionEncodeChildrenContent() {
        return encodeChildren(field.getWrappingSequence());
    }

    private byte[] encodeSequenceContent() {
        List<Asn1Encodable> children = new ArrayList<>();

        if (config.getPermittedSubtrees() != null) {
            children.add(field.getPermittedSubtrees());
        }

        if (config.getExcludedSubtrees() != null) {
            children.add(field.getExcludedSubtrees());
        }

        return encodeChildren(children);
    }
}
