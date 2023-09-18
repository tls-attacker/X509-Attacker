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
import de.rub.nds.x509attacker.x509.model.TbsCertificate;

public class TbsCertificateHandler extends X509FieldHandler<TbsCertificate> {

    public TbsCertificateHandler(X509Chooser chooser, TbsCertificate tbsCertificate) {
        super(chooser, tbsCertificate);
    }

    @Override
    public void adjustContextAfterParse() {
        throw new UnsupportedOperationException("Unimplemented method 'adjustContextAfterParse'");
    }

    @Override
    public void adjustContextAfterPrepare() {
        throw new UnsupportedOperationException("Unimplemented method 'adjustContextAfterPrepare'");
    }
}
