/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509;

import de.rub.nds.x509attacker.context.X509Context;

public class X509ChainCreationResult {
    private X509CertificateChain certificateChain;

    private X509Context context;

    public X509ChainCreationResult(X509CertificateChain certificateChain, X509Context context) {
        this.certificateChain = certificateChain;
        this.context = context;
    }

    public X509CertificateChain getCertificateChain() {
        return certificateChain;
    }

    public X509Context getContext() {
        return context;
    }
}
