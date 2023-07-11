/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.SubjectPublicKeyInfo;

public class SubjectPublicKeyInfoPreparator extends X509ContainerPreparator<SubjectPublicKeyInfo> {

    public SubjectPublicKeyInfoPreparator(
            X509Chooser chooser, SubjectPublicKeyInfo subjectPublicKeyInfo) {
        super(chooser, subjectPublicKeyInfo);
    }

    @Override
    public void prepareSubComponents() {
        field.getAlgorithm().getPreparator(chooser).prepare();
        field.getSubjectPublicKeyBitString().getPreparator(chooser).prepare();
    }

    @Override
    public byte[] encodeChildrenContent() {
        return encodeChildren(field.getAlgorithm(), field.getSubjectPublicKeyBitString());
    }
}
