/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.extension;

import de.rub.nds.asn1.model.Asn1OctetString;
import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.extension.SubjectKeyIdentifierConfig;
import de.rub.nds.x509attacker.x509.model.extensions.SubjectKeyIdentifier;

public class SubjectKeyIdentifierPreparator
        extends ExtensionPreparator<SubjectKeyIdentifier, SubjectKeyIdentifierConfig> {

    public SubjectKeyIdentifierPreparator(
            X509Chooser chooser,
            SubjectKeyIdentifier container,
            SubjectKeyIdentifierConfig config) {
        super(chooser, container, config);

        Asn1OctetString octetString = field.getKeyIdentifier();
        octetString.setContent(Asn1PreparatorHelper.encodeOctetString(config.getKeyIdentifier()));
        Asn1PreparatorHelper.prepareAfterContent(octetString);
    }

    @Override
    public void extensionPrepareSubComponents() {
        if (field.getKeyIdentifier() == null) {
            field.setKeyIdentifier(new Asn1OctetString("keyIdentifier"));
        }
    }

    @Override
    public byte[] extensionEncodeChildrenContent() {
        return encodeChildren(field.getKeyIdentifier());
    }
}
