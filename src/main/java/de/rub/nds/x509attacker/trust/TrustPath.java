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
import java.util.Arrays;
import java.util.List;

public class TrustPath {

    /**
     * A sorted list of certificates that form the trust path. The first certificate is the
     * end-entity certificate, the last certificate is the trust anchor.
     */
    private List<X509Certificate> certificateList;

    /**
     * Creates a new TrustPath. *
     *
     * @param certificateList A sorted list of certificates that form the trust path. The first
     *     certificate is the end-entity certificate, the last certificate is the trust anchor.
     */
    public TrustPath(List<X509Certificate> certificateList) {
        this.certificateList = certificateList;
    }

    public List<X509Certificate> getCertificateList() {
        return certificateList;
    }

    public X509Certificate getTrustAnchor() {
        return certificateList.get(certificateList.size() - 1);
    }

    public Boolean containsExpiredCertificate() {
        for (X509Certificate certificate : certificateList) {
            if (certificate.isExpired()) {
                return true;
            }
        }
        return false;
    }

    public Boolean containsNotYetValidCertificate() {
        for (X509Certificate certificate : certificateList) {
            if (!certificate.isYetValid()) {
                return true;
            }
        }
        return false;
    }

    public Boolean containsWeakSignature() {
        for (X509Certificate certificate : certificateList) {
            if (Arrays.equals(
                            certificate.getSha256Fingerprint(),
                            getTrustAnchor().getSha256Fingerprint())
                    && certificate.isWeakSignature()) {
                return true;
            }
        }
        return false;
    }
}
