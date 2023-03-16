/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.trust.TrustAnchor;
import de.rub.nds.x509attacker.trust.TrustPath;
import de.rub.nds.x509attacker.x509.base.X509Certificate;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;
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

    public Boolean isChainOrdered(String uri) {
        return null; // TODO Implement
    }

    public Boolean containsTrustAnchor() {
        return null; // TODO Implement
    }

    public Boolean containsKnownTrustAnchor(List<TrustAnchor> anchor) {
        return null; // TODO Implement
    }

    public Boolean containsMultipleLeafs() {
        return null; // TODO Implement
    }

    public Boolean containsValidLeaf() {
        return null; // TODO Implement
    }

    public List<TrustPath> getAllTrustPaths(List<TrustAnchor> trustAnchorList) {
        return new LinkedList<>();
    }

    public Boolean containsExpiredCertificate(TrustPath path) {
        return null; // TODO Implement
    }

    public Boolean containsExpiredCertificate() {
        return null; // TODO Implement
    }

    public Boolean containsNotYetValidCertificate(TrustPath path) {
        return null; // TODO Implement
    }

    public Boolean containsNotYetValidCertificate() {
        return null; // TODO Implement
    }

    public Boolean containsWeakSignature(TrustPath path) {
        return null; // TODO Implement
    }

    public Boolean containsSelfSignedLeaf() {
        return null; // TODO Implement
    }

    public Boolean hasIncompleteChain() {
        return null; // TODO Implement
    }

    public Boolean allSignaturesValid() {
        return null; // TODO Implement
    }

    public Boolean isExtendedValidation(){
        return null; //TODO implement
    }
}
