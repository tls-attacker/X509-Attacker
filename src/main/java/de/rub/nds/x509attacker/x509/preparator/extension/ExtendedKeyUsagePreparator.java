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
import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.extension.ExtendedKeyUsageConfig;
import de.rub.nds.x509attacker.constants.ExtendedKeyUsageType;
import de.rub.nds.x509attacker.x509.model.extensions.ExtendedKeyUsage;
import java.util.ArrayList;
import java.util.List;

public class ExtendedKeyUsagePreparator
        extends ExtensionPreparator<ExtendedKeyUsage, ExtendedKeyUsageConfig> {
    public ExtendedKeyUsagePreparator(
            X509Chooser chooser, ExtendedKeyUsage container, ExtendedKeyUsageConfig config) {
        super(chooser, container, config);
    }

    @Override
    public void extensionPrepareSubComponents() {
        List<Asn1Encodable> children = new ArrayList<>();

        for (ExtendedKeyUsageType type : config.getExtendedKeyUsages()) {
            Asn1ObjectIdentifier typeOid = new Asn1ObjectIdentifier(type.toString());
            Asn1PreparatorHelper.prepareField(typeOid, new ObjectIdentifier(type.getValue()));
            children.add(typeOid);
        }

        field.getKeyPurposeIDs().setContent(encodeChildren(children));
        Asn1PreparatorHelper.prepareAfterContent(field.getKeyPurposeIDs());
    }

    @Override
    public byte[] extensionEncodeChildrenContent() {
        return encodeChildren(field.getKeyPurposeIDs());
    }
}
