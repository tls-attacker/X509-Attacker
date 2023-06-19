/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.handler;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.model.X509Certificate;

public class X509CertificateHandler extends X509FieldHandler<X509Certificate> {

    public X509CertificateHandler(X509Chooser chooser, X509Certificate x509Certificate) {
        super(chooser, x509Certificate);
    }

    @Override
    public void adjustContext() {
        throw new UnsupportedOperationException("Unimplemented method 'adjustContext'");
    }
}
