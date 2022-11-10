/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509attacker.x509.ExplicitExtensions;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1BitString;

public class TBSCertificate extends Asn1Sequence {

    private static final Logger LOGGER = LogManager.getLogger();


    private Version version;
    private Asn1Integer serialNumber;
    private AlgorithmIdentifier signature;
    private Name issuer;
    private Validity validity;
    private Name subject;
    private SubjectPublicKeyInfo subjectPublicKeyInfo;
    private ASN1BitString issuerUniqueID;
    private ASN1BitString subjecUniqueID;
    private ExplicitExtensions explicitExtensions;

    public TBSCertificate() {
        this.setIdentifier("tbsCertificate");
    }

    public Version getVersion() {
        return version;
    }

    public void setVersion(Version version) {
        this.version = version;
    }

    public Asn1Integer getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(Asn1Integer serialNumber) {
        this.serialNumber = serialNumber;
    }

    public AlgorithmIdentifier getSignature() {
        return signature;
    }

    public void setSignature(AlgorithmIdentifier signature) {
        this.signature = signature;
    }

    public Name getIssuer() {
        return issuer;
    }

    public void setIssuer(Name issuer) {
        this.issuer = issuer;
    }

    public Validity getValidity() {
        return validity;
    }

    public void setValidity(Validity validity) {
        this.validity = validity;
    }

    public Name getSubject() {
        return subject;
    }

    public void setSubject(Name subject) {
        this.subject = subject;
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
        return subjectPublicKeyInfo;
    }

    public void setSubjectPublicKeyInfo(SubjectPublicKeyInfo subjectPublicKeyInfo) {
        this.subjectPublicKeyInfo = subjectPublicKeyInfo;
    }

    public UniqueIdentifier getIssuerUniqueID() {
        return issuerUniqueID;
    }

    public void setIssuerUniqueID(UniqueIdentifier issuerUniqueID) {
        this.issuerUniqueID = issuerUniqueID;
    }

    public UniqueIdentifier getSubjecUniqueID() {
        return subjecUniqueID;
    }

    public void setSubjecUniqueID(UniqueIdentifier subjecUniqueID) {
        this.subjecUniqueID = subjecUniqueID;
    }

    public ExplicitExtensions getExplicitExtensions() {
        return explicitExtensions;
    }

    public void setExplicitExtensions(ExplicitExtensions explicitExtensions) {
        this.explicitExtensions = explicitExtensions;
    }

}
