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
import de.rub.nds.x509attacker.config.extension.BasicConstraintsConfig;
import de.rub.nds.x509attacker.constants.DefaultEncodingRule;
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
        Asn1PreparatorHelper.prepareField(field.getCa(), config.isCa());
        Asn1PreparatorHelper.prepareField(
                field.getPathLenConstraint(), BigInteger.valueOf(config.getPathLenConstraint()));

        field.getWrappingSequence().setContent(encodeSequenceContent());
        Asn1PreparatorHelper.prepareAfterContent(field.getWrappingSequence());
    }

    private byte[] encodeSequenceContent() {
        List<Asn1Encodable> children = new ArrayList<>();
        // per default only include if CA is true
        if (config.getIncludeCA() == DefaultEncodingRule.ENCODE
                || config.getIncludeCA() == DefaultEncodingRule.FOLLOW_DEFAULT
                        && field.getCa().getValue().getValue()) {
            children.add(field.getCa());
        }
        // by default only include if CA is true
        if (config.getIncludePathLenConstraint() == DefaultEncodingRule.ENCODE
                || config.getIncludePathLenConstraint() == DefaultEncodingRule.FOLLOW_DEFAULT
                        && field.getCa().getValue().getValue()) {
            children.add(field.getPathLenConstraint());
        }
        return encodeChildren(children);
    }

    @Override
    public byte[] extensionEncodeChildrenContent() {
        return encodeChildren(field.getWrappingSequence());
    }
}
