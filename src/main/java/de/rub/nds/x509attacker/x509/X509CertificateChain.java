/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.trust.TrustPath;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.security.cert.TrustAnchor;
import java.util.LinkedList;
import java.util.List;

/**
 * Represent one X509CertificateChain containing multiple X509Certificates and provides an API for
 * accessing and modifying the chain.
 */
@XmlRootElement(name = "X509CertificateChain")
@XmlAccessorType(XmlAccessType.FIELD)
public class X509CertificateChain {

    @XmlElementWrapper(name = "X509Certificates")
    @XmlElement(name = "X509Certificate")
    @HoldsModifiableVariable
    private List<X509Certificate> certificateList = new LinkedList<>();

    public X509CertificateChain() {}

    public X509CertificateChain(List<X509Certificate> certChain) {
        this.certificateList = certChain;
    }

    public void addCertificate(int index, X509Certificate certificate) {
        certificateList.add(index, certificate);
    }

    public void addCertificate(X509Certificate certificate) {
        certificateList.add(certificate);
    }

    public void removeCertificate(int index) {
        certificateList.remove(index);
    }

    public int size() {
        return certificateList.size();
    }

    public X509Certificate getCertificate(int index) {
        if (index <= certificateList.size() - 1) {
            return certificateList.get(index);
        } else {
            return null;
        }
    }

    public List<X509Certificate> getCertificateList() {
        return certificateList;
    }

    public void setCertificateList(List<X509Certificate> certificateList) {
        this.certificateList = certificateList;
    }

    /**
     * TODO This is currently returning the first certificate in the chain
     *
     * @return
     */
    public X509Certificate getLeaf() {
        if (!certificateList.isEmpty()) {
            return certificateList.get(0);
        } else {
            return null;
        }
    }

    public Boolean isChainOrdered() {
        throw new UnsupportedOperationException("isChainOrdered is not yet implemented");
    }

    /**
     * A chain is considered to contain a trust anchor if it contains a self signed certificate.
     *
     * @return
     */
    public Boolean containsTrustAnchor() {
        for (X509Certificate certificate : certificateList) {
            if (certificate.isSelfSigned()) {
                return true;
            }
        }
        return false;
    }

    public Boolean containsKnownTrustAnchor(List<TrustAnchor> anchor) {
        throw new UnsupportedOperationException("containsKnownTrustAnchor is not yet implemented");
    }

    public Boolean containsMultipleLeafs() {
        int counter = 0;
        for (X509Certificate certificate : certificateList) {
            if (certificate.isLeaf()) {
                counter++;
            }
        }
        return counter <= 1;
    }

    /**
     * A valid leaf is a leaf for which the uri would match either the CN or SAN, this does not
     * check the trust path
     *
     * @param uri
     * @return
     */
    public Boolean containsValidLeaf(String uri) {
        for (X509Certificate certificate : certificateList) {
            if (certificate.isValidLeafForUri(uri)) {
                return true;
            }
        }
        return false;
    }

    public List<TrustPath> getAllTrustPaths(List<X509Certificate> trustAnchorList) {
        return new LinkedList<>();
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

    public Boolean containsSelfSignedLeaf() {
        for (X509Certificate certificate : certificateList) {
            if (certificate.isLeaf() && certificate.isSelfSigned()) {
                return true;
            }
        }
        return false;
    }

    public Boolean hasIncompleteChain() {
        throw new UnsupportedOperationException("hasIncompleteChain is not implemented yet");
    }

    public Boolean allSignaturesValid() {
        for (X509Certificate certificate : certificateList) {
            if (!certificate.isSignatureValid()) {
                return false;
            }
        }
        return true;
    }

    public Boolean isExtendedValidation() {
        throw new UnsupportedOperationException("isExtendedValidation is not implemented yet");
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((certificateList == null) ? 0 : certificateList.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        X509CertificateChain other = (X509CertificateChain) obj;
        if (certificateList == null) {
            if (other.certificateList != null) return false;
        } else if (!certificateList.equals(other.certificateList)) return false;
        return true;
    }
}
