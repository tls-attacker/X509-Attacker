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
import de.rub.nds.x509attacker.config.extension.PolicyConstraintsConfig;
import de.rub.nds.x509attacker.x509.model.extensions.PolicyConstraints;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class PolicyConstraintsPreparator
        extends ExtensionPreparator<PolicyConstraints, PolicyConstraintsConfig> {

    public PolicyConstraintsPreparator(
            X509Chooser chooser, PolicyConstraints container, PolicyConstraintsConfig config) {
        super(chooser, container, config);
    }

    @Override
    public void extensionPrepareSubComponents() {
        // TODO: Probably refactor into Asn1 classes that hold context-specific tags

        if (config.isIncludeRequired()) {
            Asn1PreparatorHelper.prepareField(
                    field.getRequireExplicitPolicy(),
                    BigInteger.valueOf(config.getSkipCertsRequired()));

            // set context-specific tag
            field.getRequireExplicitPolicy().setTagOctets(new byte[] {(byte) 0x80});

            // set outer length
            field.getRequireExplicitPolicy()
                    .setLengthOctets(
                            new byte[] {
                                (byte)
                                        (field.getRequireExplicitPolicy()
                                                .getContent()
                                                .getValue()
                                                .length)
                            });
        }

        if (config.isIncludeInhibit()) {
            Asn1PreparatorHelper.prepareField(
                    field.getInhibitPolicyMapping(),
                    BigInteger.valueOf(config.getSkipCertsInhibit()));

            // set context-specific tag
            field.getInhibitPolicyMapping().setTagOctets(new byte[] {(byte) 0x81});

            // set outer length
            field.getInhibitPolicyMapping()
                    .setLengthOctets(
                            new byte[] {
                                (byte)
                                        (field.getInhibitPolicyMapping()
                                                .getContent()
                                                .getValue()
                                                .length)
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

        if (config.isIncludeRequired()) {
            children.add(field.getRequireExplicitPolicy());
        }

        if (config.isIncludeInhibit()) {
            children.add(field.getInhibitPolicyMapping());
        }

        return encodeChildren(children);
    }
}
