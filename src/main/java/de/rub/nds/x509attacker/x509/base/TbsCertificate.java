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
import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.parser.X509ComponentParser;
import de.rub.nds.x509attacker.x509.preparator.X509ComponentPreparator;
import de.rub.nds.x509attacker.x509.serializer.X509ComponentSerializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TbsCertificate extends Asn1Sequence implements X509Component {

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
    private Asn1PrimitiveBitString issuerUniqueID;

    @HoldsModifiableVariable
    private Asn1PrimitiveBitString subjectUniqueID;

    @HoldsModifiableVariable
    private Extensions extensions;

    public TbsCertificate(String identifier, X509CertificateConfig config) {
        super(identifier);
        version = new Version("version");
        serialNumber = new Asn1Integer("serialNumber");
        signature = new AlgorithmIdentifier("signature");
        issuer = new Name("issuer", config.getIssuer());
        validity = new Validity("validity");
        subject = new Name("subject", config.getSubject());
        subjectPublicKeyInfo = new SubjectPublicKeyInfo("subjectPublicKeyInfo", config);
        issuerUniqueID = new Asn1PrimitiveBitString("issuerUniqueID");
        subjectUniqueID = new Asn1PrimitiveBitString("issuerUniqueID");
        extensions = new Extensions("extensions");
        addChild(version);
        addChild(serialNumber);
        addChild(signature);
        addChild(issuer);
        addChild(validity);
        addChild(subject);
        addChild(subjectPublicKeyInfo);
        addChild(issuerUniqueID);
        addChild(subjectUniqueID);
        addChild(extensions);
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

    public Asn1PrimitiveBitString getIssuerUniqueID() {
        return issuerUniqueID;
    }

    public void setIssuerUniqueID(Asn1PrimitiveBitString issuerUniqueID) {
        this.issuerUniqueID = issuerUniqueID;
    }

    public Asn1PrimitiveBitString getSubjectUniqueID() {
        return subjectUniqueID;
    }

    public void setSubjectUniqueID(Asn1PrimitiveBitString subjectUniqueID) {
        this.subjectUniqueID = subjectUniqueID;
    }

    public Extensions getExtensions() {
        return extensions;
    }

    public void setExtensions(Extensions extensions) {
        this.extensions = extensions;
    }

    @Override
    public X509ComponentPreparator getPreparator() {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public X509ComponentParser getParser() {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public X509ComponentSerializer getSerializer() {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

}
