/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.asn1.model.Asn1BitString;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.NameType;
import de.rub.nds.x509attacker.x509.handler.TbsCertificateHandler;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.parser.TbsCertificateParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.TbsCertificatePreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import de.rub.nds.x509attacker.x509.serializer.X509Asn1FieldSerializer;
import de.rub.nds.x509attacker.x509.serializer.X509Serializer;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class TbsCertificate extends Asn1Sequence implements X509Component {

    @HoldsModifiableVariable private X509Explicit<Version> version;

    @HoldsModifiableVariable private Asn1Integer serialNumber;

    @HoldsModifiableVariable private CertificateSignatureAlgorithmIdentifier signature;

    @HoldsModifiableVariable private Name issuer;

    @HoldsModifiableVariable private Validity validity;

    @HoldsModifiableVariable private Name subject;

    @HoldsModifiableVariable private SubjectPublicKeyInfo subjectPublicKeyInfo;

    @HoldsModifiableVariable private Asn1BitString issuerUniqueId;

    @HoldsModifiableVariable private Asn1BitString subjectUniqueId;

    @HoldsModifiableVariable private X509Explicit<Extensions> explicitExtensions;

    private TbsCertificate() {
        super(null);
    }

    public TbsCertificate(String identifier, X509CertificateConfig config) {
        super(identifier);
        version = new X509Explicit<Version>("versionExplicit", 0, new Version("version"));
        version.setOptional(true);
        serialNumber = new Asn1Integer("serialNumber");
        signature = new CertificateSignatureAlgorithmIdentifier("signature");
        issuer = new Name("issuer", NameType.ISSUER, config.getDefaultIssuer());
        validity = new Validity("validity");
        subject = new Name("subject", NameType.SUBJECT, config.getSubject());
        subjectPublicKeyInfo = new SubjectPublicKeyInfo("subjectPublicKeyInfo", config);
        if (config.isIncludeIssuerUniqueId()) {
            issuerUniqueId = new Asn1BitString("issuerUniqueID", 1);
            issuerUniqueId.setOptional(true);
        }
        if (config.isIncludeSubjectUniqueId()) {
            subjectUniqueId = new Asn1BitString("subjectUniqueID", 2);
            subjectUniqueId.setOptional(true);
        }
        if (config.isIncludeExtensions()) {
            explicitExtensions =
                    new X509Explicit<Extensions>(
                            "extensionsExplicit", 3, new Extensions("extensions"));
        }
        addChild(version);
        addChild(serialNumber);
        addChild(signature);
        addChild(issuer);
        addChild(validity);
        addChild(subject);
        addChild(subjectPublicKeyInfo);
        if (issuerUniqueId != null) {
            addChild(issuerUniqueId);
        }
        if (subjectUniqueId != null) {
            addChild(subjectUniqueId);
        }
        if (explicitExtensions != null) {
            addChild(explicitExtensions);
        }
    }

    public TbsCertificate(String identifier) {
        super(identifier);
        version = new X509Explicit<Version>("versionExplicit", 0, new Version("version"));
        version.setOptional(true);
        serialNumber = new Asn1Integer("serialNumber");
        signature = new CertificateSignatureAlgorithmIdentifier("signature");
        issuer = new Name("issuer", NameType.ISSUER);
        validity = new Validity("validity");
        subject = new Name("subject", NameType.SUBJECT);
        subjectPublicKeyInfo = new SubjectPublicKeyInfo("subjectPublicKeyInfo");
        issuerUniqueId = new Asn1BitString("issuerUniqueID", 1);
        issuerUniqueId.setOptional(true);
        subjectUniqueId = new Asn1BitString("subjectUniqueID", 2);
        subjectUniqueId.setOptional(true);
        explicitExtensions =
                new X509Explicit<Extensions>("extensionsExplicit", 3, new Extensions("extensions"));
        explicitExtensions.setOptional(true);
        addChild(version);
        addChild(serialNumber);
        addChild(signature);
        addChild(issuer);
        addChild(validity);
        addChild(subject);
        addChild(subjectPublicKeyInfo);
        addChild(issuerUniqueId);
        addChild(subjectUniqueId);
        addChild(explicitExtensions);
    }

    public Asn1Integer getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(Asn1Integer serialNumber) {
        this.serialNumber = serialNumber;
    }

    public CertificateSignatureAlgorithmIdentifier getSignature() {
        return signature;
    }

    public void setSignature(CertificateSignatureAlgorithmIdentifier signature) {
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

    public Asn1BitString getIssuerUniqueId() {
        return issuerUniqueId;
    }

    public void setIssuerUniqueId(Asn1BitString issuerUniqueID) {
        this.issuerUniqueId = issuerUniqueID;
    }

    public Asn1BitString getSubjectUniqueId() {
        return subjectUniqueId;
    }

    public void setSubjectUniqueId(Asn1BitString subjectUniqueID) {
        this.subjectUniqueId = subjectUniqueID;
    }

    public X509Explicit<Extensions> getExplicitExtensions() {
        return explicitExtensions;
    }

    public void setExplicitExtensions(X509Explicit<Extensions> explicitExtensions) {
        this.explicitExtensions = explicitExtensions;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new TbsCertificateHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new TbsCertificateParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new TbsCertificatePreparator(chooser, this);
    }

    @Override
    public X509Serializer getSerializer(X509Chooser chooser) {
        return new X509Asn1FieldSerializer(this);
    }

    public X509Explicit<Version> getVersion() {
        return version;
    }

    public void setVersion(X509Explicit<Version> version) {
        this.version = version;
    }
}
