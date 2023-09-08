/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.trust;

import de.rub.nds.x509attacker.x509.model.X509Certificate;

public class TrustAnchor {
    private final X509Certificate certificate;
    private final byte[] sha256Fingerprint;

    public TrustAnchor(X509Certificate certificate) {
        this.certificate = certificate;
        sha256Fingerprint = certificate.getSha256Fingerprint();
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public byte[] getSha256Fingerprint() {
        return sha256Fingerprint;
    }
}
