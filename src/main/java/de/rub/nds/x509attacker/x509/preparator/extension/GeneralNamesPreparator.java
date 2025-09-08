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
import de.rub.nds.x509attacker.x509.model.extensions.GeneralNames;
import de.rub.nds.x509attacker.x509.preparator.X509ContainerPreparator;
import java.util.ArrayList;
import java.util.List;

public class GeneralNamesPreparator extends X509ContainerPreparator<GeneralNames> {

    private final X509Chooser chooser;
    private final GeneralNames generalNames;

    public GeneralNamesPreparator(X509Chooser chooser, GeneralNames generalNames) {
        super(chooser, generalNames);
        this.chooser = chooser;
        this.generalNames = generalNames;
    }

    @Override
    public void prepareSubComponents() {
        generalNames
                .getGeneralNames()
                .forEach(generalName -> generalName.getPreparator(chooser).prepare());
    }

    @Override
    public byte[] encodeChildrenContent() {
        List<Asn1Encodable> children = new ArrayList<>(generalNames.getGeneralNames());
        return encodeChildren(children);
    }
}
