/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.extension;

import de.rub.nds.asn1.model.Asn1Ia5String;
import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.extensions.PolicyQualifierInfo;
import de.rub.nds.x509attacker.x509.preparator.X509ContainerPreparator;

public class PolicyQualifierInfoPreparator extends X509ContainerPreparator<PolicyQualifierInfo> {
    public PolicyQualifierInfoPreparator(X509Chooser chooser, PolicyQualifierInfo container) {
        super(chooser, container);
    }

    @Override
    public void prepareSubComponents() {
        Asn1PreparatorHelper.prepareField(
                field.getPolicyQualifierId(), field.getPolicyObjectIdentifier());

        Asn1PreparatorHelper.prepareField(
                (Asn1Ia5String) field.getQualifier(), field.getQualifierString());
    }

    @Override
    public byte[] encodeChildrenContent() {
        return encodeChildren(field.getPolicyQualifierId());
    }
}
