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
import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.extensions.PolicyInformation;
import de.rub.nds.x509attacker.x509.preparator.X509ContainerPreparator;
import java.util.ArrayList;
import java.util.List;

public class PolicyInformationPreparator extends X509ContainerPreparator<PolicyInformation> {
    public PolicyInformationPreparator(X509Chooser chooser, PolicyInformation container) {
        super(chooser, container);
    }

    @Override
    public void prepareSubComponents() {
        Asn1PreparatorHelper.prepareField(
                field.getPolicyIdentifier(),
                new ObjectIdentifier(field.getPolicyIdentifierContent()));

        if (field.getIncludeQualifiers()) {
            field.getPolicyQualifiers().getPreparator(chooser).prepare();
        }
    }

    @Override
    public byte[] encodeChildrenContent() {
        List<Asn1Encodable> children = new ArrayList<>();
        children.add(field.getPolicyIdentifier());
        if (field.getIncludeQualifiers()) {
            children.add(field.getPolicyQualifiers());
        }
        return encodeChildren(children);
    }
}
