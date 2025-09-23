/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.config.extension;

import de.rub.nds.x509attacker.constants.X509ExtensionType;
import de.rub.nds.x509attacker.x509.model.AttributeValueSet;
import de.rub.nds.x509attacker.x509.model.extensions.SubjectDirectoryAttributes;
import java.util.List;

public class SubjectDirectoryAttributesConfig extends ExtensionConfig {

    private List<String> identifier;
    private List<AttributeValueSet> attributeValueSets;

    public SubjectDirectoryAttributesConfig() {
        super(
                X509ExtensionType.SUBJECT_DIRECTORY_ATTRIBUTES.getOid(),
                "subjectDirectoryAttributes");
    }

    @Override
    public SubjectDirectoryAttributes getExtensionFromConfig() {
        return new SubjectDirectoryAttributes("subjectDirectoryAttributes");
    }

    public List<String> getIdentifier() {
        return identifier;
    }

    public void setIdentifier(List<String> identifier) {
        this.identifier = identifier;
    }

    public List<AttributeValueSet> getAttributeValueSets() {
        return attributeValueSets;
    }

    public void setAttributeValueSets(List<AttributeValueSet> attributeValueSets) {
        this.attributeValueSets = attributeValueSets;
    }
}
