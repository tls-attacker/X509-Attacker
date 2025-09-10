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
import de.rub.nds.x509attacker.config.extension.InhibitAnyPolicyConfig;
import de.rub.nds.x509attacker.x509.model.extensions.InhibitAnyPolicy;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class InhibitAnyPolicyPreparator
        extends ExtensionPreparator<InhibitAnyPolicy, InhibitAnyPolicyConfig> {

    public InhibitAnyPolicyPreparator(
            X509Chooser chooser, InhibitAnyPolicy inhibitAnyPolicy, InhibitAnyPolicyConfig config) {
        super(chooser, inhibitAnyPolicy, config);
    }

    @Override
    public void extensionPrepareSubComponents() {
        Asn1PreparatorHelper.prepareField(
                field.getSkipCerts(), BigInteger.valueOf(config.getSkipCerts()));
    }

    @Override
    public byte[] extensionEncodeChildrenContent() {
        List<Asn1Encodable> children = new ArrayList<>();
        children.add(field.getSkipCerts());
        return encodeChildren(children);
    }
}
