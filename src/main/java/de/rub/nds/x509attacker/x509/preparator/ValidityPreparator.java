/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.Validity;

public class ValidityPreparator extends X509ContainerPreparator<Validity> {

    public ValidityPreparator(X509Chooser chooser, Validity validity) {
        super(chooser, validity);
    }

    @Override
    public void prepareSubComponents() {
        prepareNotBefore();
        prepareNotAfter();
    }

    private void prepareNotBefore() {
        field.getNotBefore().getPreparator(chooser).prepare();
        field.getNotBefore().getHandler(chooser).adjustContextAfterPrepare();
    }

    private void prepareNotAfter() {
        field.getNotAfter().getPreparator(chooser).prepare();
        field.getNotAfter().getHandler(chooser).adjustContextAfterPrepare();
    }

    @Override
    public byte[] encodeChildrenContent() {
        return encodeChildren(field.getNotBefore(), field.getNotAfter());
    }
}
