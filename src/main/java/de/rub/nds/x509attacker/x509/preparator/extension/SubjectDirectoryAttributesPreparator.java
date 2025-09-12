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
import de.rub.nds.x509attacker.config.extension.SubjectDirectoryAttributesConfig;
import de.rub.nds.x509attacker.x509.model.extensions.SubjectDirectoryAttributes;
import java.util.ArrayList;
import java.util.List;

public class SubjectDirectoryAttributesPreparator
        extends ExtensionPreparator<SubjectDirectoryAttributes, SubjectDirectoryAttributesConfig> {

    public SubjectDirectoryAttributesPreparator(
            X509Chooser chooser,
            SubjectDirectoryAttributes container,
            SubjectDirectoryAttributesConfig config) {
        super(chooser, container, config);
    }

    @Override
    public void extensionPrepareSubComponents() {
        List<Asn1Encodable> children = new ArrayList<>();
        for (int i = 0; i < config.getAttributeValueSets().size(); i++) {
            Asn1UnknownSequence innerSequence = new Asn1UnknownSequence("attribute");
            config.getAttributeValueSets().get(i).getPreparator(chooser).prepare();
            Asn1ObjectIdentifier type =
                    Asn1PreparatorHelper.prepareField(
                            null, new ObjectIdentifier(config.getIdentifier().get(i)));
            innerSequence.setContent(encodeChildren(type, config.getAttributeValueSets().get(i)));
            Asn1PreparatorHelper.prepareAfterContent(innerSequence);
            children.add(innerSequence);
        }
        field.getAttributes().setContent(encodeChildren(children));
        Asn1PreparatorHelper.prepareAfterContent(field.getAttributes());
    }

    @Override
    public byte[] extensionEncodeChildrenContent() {
        return encodeChildren(field.getAttributes());
    }
}
