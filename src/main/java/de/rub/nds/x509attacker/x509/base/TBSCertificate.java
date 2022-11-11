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
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.ASN1BitString;

public class TBSCertificate extends Asn1Sequence {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable
    private Version version;

    @HoldsModifiableVariable
    private Asn1Integer serialNumber;

    @HoldsModifiableVariable
    private AlgorithmIdentifier signature;

    @HoldsModifiableVariable
    private Name issuer;

    @HoldsModifiableVariable
    private Validity validity;

    @HoldsModifiableVariable
    private Name subject;

    @HoldsModifiableVariable
    private SubjectPublicKeyInfo subjectPublicKeyInfo;

    @HoldsModifiableVariable
    private ASN1BitString issuerUniqueID;

    @HoldsModifiableVariable
    private ASN1BitString subjecUniqueID;

    @HoldsModifiableVariable
    private Extensions extensions;

    public TBSCertificate(String identifier) {
        super(identifier);
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

    public ASN1BitString getIssuerUniqueID() {
        return issuerUniqueID;
    }

    public void setIssuerUniqueID(ASN1BitString issuerUniqueID) {
        this.issuerUniqueID = issuerUniqueID;
    }

    public ASN1BitString getSubjecUniqueID() {
        return subjecUniqueID;
    }

    public void setSubjecUniqueID(ASN1BitString subjecUniqueID) {
        this.subjecUniqueID = subjecUniqueID;
    }

    public Extensions getExtensions() {
        return extensions;
    }

    public void setExtensions(Extensions extensions) {
        this.extensions = extensions;
    }
}
