/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.extension;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.extensions.PolicyQualifierInfo;
import de.rub.nds.x509attacker.x509.model.extensions.PolicyQualifiers;
import de.rub.nds.x509attacker.x509.preparator.X509ContainerPreparator;

public class PolicyQualifiersPreparator extends X509ContainerPreparator<PolicyQualifiers> {
    public PolicyQualifiersPreparator(X509Chooser chooser, PolicyQualifiers container) {
        super(chooser, container);
    }

    @Override
    public void prepareSubComponents() {
        for (PolicyQualifierInfo policyQualifierInfo : field.getPolicyQualifierInfo()) {
            policyQualifierInfo.getPreparator(chooser).prepare();
        }
    }

    @Override
    public byte[] encodeChildrenContent() {
        return encodeChildren(field.getPolicyQualifierInfo().toArray(new PolicyQualifierInfo[0]));
    }
}
