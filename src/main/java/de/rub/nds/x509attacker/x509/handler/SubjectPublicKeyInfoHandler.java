/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.handler;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.SubjectPublicKeyInfo;

public class SubjectPublicKeyInfoHandler extends X509FieldHandler<SubjectPublicKeyInfo> {

    public SubjectPublicKeyInfoHandler(
            X509Chooser chooser, SubjectPublicKeyInfo subjectPublicKeyInfo) {
        super(chooser, subjectPublicKeyInfo);
    }

    @Override
    public void adjustContextAfterParse() {
        // Nothing to do right now
    }

    @Override
    public void adjustContextAfterPrepare() {
        // Nothing to do right now
    }
}