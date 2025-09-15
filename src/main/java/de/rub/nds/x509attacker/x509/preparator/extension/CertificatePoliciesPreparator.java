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
import de.rub.nds.x509attacker.config.extension.CertificatePoliciesConfig;
import de.rub.nds.x509attacker.x509.model.extensions.CertificatePolicies;
import de.rub.nds.x509attacker.x509.model.extensions.PolicyInformation;
import java.util.ArrayList;
import java.util.List;

public class CertificatePoliciesPreparator
        extends ExtensionPreparator<CertificatePolicies, CertificatePoliciesConfig> {
    public CertificatePoliciesPreparator(
            X509Chooser chooser, CertificatePolicies container, CertificatePoliciesConfig config) {
        super(chooser, container, config);
    }

    @Override
    public void extensionPrepareSubComponents() {
        List<PolicyInformation> policyInformationList = new ArrayList<>();
        List<Asn1Encodable> children = new ArrayList<>();
        for (int i = 0; i < config.getPolicyIdentifiers().size(); i++) {
            PolicyInformation policyInformation = new PolicyInformation("policyInformation " + i);
            policyInformation.setPolicyIdentifierContent(config.getPolicyIdentifiers().get(i));
            policyInformation.setIncludeQualifiers(config.getIncludeQualifiers().get(i));
            policyInformation.setPolicyQualifiers(config.getPolicyQualifiers().get(i));
            policyInformation.getPreparator(chooser).prepare();
            policyInformationList.add(policyInformation);
            children.add(policyInformation);
        }
        field.setPolicyInformation(policyInformationList);

        field.getWrappingSequence().setContent(encodeChildren(children));
        Asn1PreparatorHelper.prepareAfterContent(field.getWrappingSequence());
    }

    @Override
    public byte[] extensionEncodeChildrenContent() {
        return encodeChildren(field.getWrappingSequence());
    }
}
