/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.trust;

import de.rub.nds.x509attacker.x509.base.X509Certificate;
import java.util.List;

public class TrustPath {

    private List<X509Certificate> certificateList;

    public TrustPath(List<X509Certificate> certificateList) {
        this.certificateList = certificateList;
    }

    public List<X509Certificate> getCertificateList() {
        return certificateList;
    }

    public void setCertificateList(List<X509Certificate> certificateList) {
        this.certificateList = certificateList;
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
        return null; // TODO Implement
    }

}
