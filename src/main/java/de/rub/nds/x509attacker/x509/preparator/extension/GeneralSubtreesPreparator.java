/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.extension;

import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.extensions.GeneralSubtrees;
import de.rub.nds.x509attacker.x509.preparator.X509ContainerPreparator;
import java.util.ArrayList;

public class GeneralSubtreesPreparator extends X509ContainerPreparator<GeneralSubtrees> {

    private final GeneralSubtrees generalSubtrees;

    public GeneralSubtreesPreparator(X509Chooser chooser, GeneralSubtrees generalSubtrees) {
        super(chooser, generalSubtrees);

        this.generalSubtrees = generalSubtrees;
    }

    @Override
    public void prepareSubComponents() {
        generalSubtrees
                .getGeneralSubtrees()
                .forEach(generalName -> generalName.getPreparator(chooser).prepare());
        field.getWrappingSequence()
                .setContent(encodeChildren(new ArrayList<>(generalSubtrees.getGeneralSubtrees())));
        Asn1PreparatorHelper.prepareAfterContent(field.getWrappingSequence());
    }

    @Override
    public byte[] encodeChildrenContent() {
        return encodeChildren(field.getWrappingSequence());
    }
}
