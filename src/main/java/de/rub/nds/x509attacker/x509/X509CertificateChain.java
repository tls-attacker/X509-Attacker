/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Represent one X509CertificateChain containing multiple X509Certificates and provides an API for accessing and
 * modifying the chain.
 */
@XmlRootElement(name = "X509CertificateChain")
@XmlAccessorType(XmlAccessType.FIELD)
public class X509CertificateChain {

    private static final Logger LOGGER = LogManager.getLogger(X509CertificateChain.class);

    @XmlElementWrapper(name = "X509Certificates")
    @XmlElement(name = "X509Certificate")
    @HoldsModifiableVariable
    private List<X509Certificate> certificateList = new LinkedList<>();

    public X509CertificateChain() {
    }

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
}
