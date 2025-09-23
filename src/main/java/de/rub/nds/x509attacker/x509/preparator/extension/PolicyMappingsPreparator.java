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
import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.asn1.model.Asn1UnknownSequence;
import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.extension.PolicyMappingsConfig;
import de.rub.nds.x509attacker.x509.model.extensions.PolicyMappings;
import java.util.ArrayList;
import java.util.List;

public class PolicyMappingsPreparator
        extends ExtensionPreparator<PolicyMappings, PolicyMappingsConfig> {
    public PolicyMappingsPreparator(
            X509Chooser chooser, PolicyMappings container, PolicyMappingsConfig config) {
        super(chooser, container, config);
    }

    @Override
    public void extensionPrepareSubComponents() {
        List<Asn1Encodable> innerSequences = new ArrayList<>();
        for (int i = 0; i < config.getSubjectDomainPolicies().size(); i++) {
            Asn1UnknownSequence innerSequence = new Asn1UnknownSequence("innerSequence" + i);
            Asn1ObjectIdentifier innerIssuer =
                    Asn1PreparatorHelper.prepareField(
                            null, new ObjectIdentifier(config.getIssuerDomainPolicies().get(i)));
            Asn1ObjectIdentifier innerSubject =
                    Asn1PreparatorHelper.prepareField(
                            null, new ObjectIdentifier(config.getSubjectDomainPolicies().get(i)));

            innerSequence.setContent(encodeChildren(List.of(innerIssuer, innerSubject)));
            Asn1PreparatorHelper.prepareAfterContent(innerSequence);
            innerSequences.add(innerSequence);
        }
        field.getPolicyMappings().setContent(encodeChildren(innerSequences));
        Asn1PreparatorHelper.prepareAfterContent(field.getPolicyMappings());
    }

    @Override
    public byte[] extensionEncodeChildrenContent() {
        return encodeChildren(field.getPolicyMappings());
    }
}
