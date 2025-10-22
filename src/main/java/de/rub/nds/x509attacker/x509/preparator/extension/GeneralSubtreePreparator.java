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
import de.rub.nds.x509attacker.x509.model.extensions.GeneralSubtree;
import de.rub.nds.x509attacker.x509.preparator.X509ContainerPreparator;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class GeneralSubtreePreparator extends X509ContainerPreparator<GeneralSubtree> {

    private final X509Chooser chooser;

    public GeneralSubtreePreparator(X509Chooser chooser, GeneralSubtree generalSubtree) {
        super(chooser, generalSubtree);

        this.chooser = chooser;
    }

    @Override
    public void prepareSubComponents() {
        field.getBase().getPreparator(chooser).prepare();

        // TODO: Probably refactor into Asn1 classes that hold context-specific tags
        if (field.isIncludeMinimum()) {
            Asn1PreparatorHelper.prepareField(
                    field.getMinimum(), BigInteger.valueOf(field.getMinimumValue()));

            // set context-specific tag
            field.getMinimum().setTagOctets(new byte[] {(byte) 0x80});

            // set outer length
            field.getMinimum()
                    .setLengthOctets(
                            new byte[] {
                                (byte) (field.getMinimum().getContent().getValue().length)
                            });
        }

        if (field.isIncludeMaximum()) {
            Asn1PreparatorHelper.prepareField(
                    field.getMaximum(), BigInteger.valueOf(field.getMaximumValue()));

            // set context-specific tag
            field.getMaximum().setTagOctets(new byte[] {(byte) 0x81});

            // set outer length
            field.getMaximum()
                    .setLengthOctets(
                            new byte[] {
                                (byte) (field.getMaximum().getContent().getValue().length)
                            });
        }
    }

    @Override
    public byte[] encodeChildrenContent() {
        List<Asn1Encodable> children = new ArrayList<>();
        children.add(field.getBase());

        if (field.isIncludeMinimum()) {
            children.add(field.getMinimum());
        }

        if (field.isIncludeMaximum()) {
            children.add(field.getMaximum());
        }

        return encodeChildren(children);
    }
}
