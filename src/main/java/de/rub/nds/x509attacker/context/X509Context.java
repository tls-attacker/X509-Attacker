/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.context;

import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

public class X509Context {

    private BigInteger issuerRsaPrivateKey = null;

    private BigInteger issuerRsaModulus = null;

    private BigInteger issuerDsaPublicKeyY = null;

    private BigInteger issuerDsaPrivateKey = null;

    private BigInteger issuerEcPrivateKey = null;

    private X509PublicKeyType issuerPublicKeyType = null;

    private byte[] issuerUniqueId = null;

    private X509NamedCurve issuerNamedCurve = null;

    private List<Pair<X500AttributeType, String>> issuer = null;

    private List<Pair<X500AttributeType, String>> subject = null;

    private BigInteger subjectRsaPrivateKey = null;

    private BigInteger subjectRsaModulus = null;

    private BigInteger subjectRsaPublicExponent = null;

    private BigInteger subjectDsaPublicKeyY = null;

    private BigInteger subjectDsaPrivateKey = null;

    private BigInteger subjectEcPrivateKey = null;

    private Point subjectEcPublicKey = null;

    private X509SignatureAlgorithm subjectSignatureAlgorithm;

    private X509PublicKeyType subjectPublicKeyType = null;

    private X509NamedCurve subjectNamedCurve = null;

    private BigInteger subjectDhPrivateKey = null;

    private BigInteger subjectDhPublicKey = null;

    private BigInteger subjectDhModulus = null;

    private BigInteger subjectDhGenerator = null;

    private X509CertificateConfig config;

    private X509Chooser chooser;

    public X509Context() {
        this(new X509CertificateConfig());
    }

    public X509Context(X509CertificateConfig config) {
        this.config = config;
        this.chooser = new X509Chooser(config, this);
    }

    public X509CertificateConfig getConfig() {
        return config;
    }

    public void setConfig(X509CertificateConfig config) {
        this.config = config;
        this.chooser = new X509Chooser(config, this);
    }

    public X509Chooser getChooser() {
        return chooser;
    }

    public BigInteger getSubjectDhPrivateKey() {
        return subjectDhPrivateKey;
    }

    public void setSubjectDhPrivateKey(BigInteger subjectDhPrivateKey) {
        this.subjectDhPrivateKey = subjectDhPrivateKey;
    }

    public BigInteger getSubjectDhModulus() {
        return subjectDhModulus;
    }

    public void setSubjectDhModulus(BigInteger subjectDhModulus) {
        this.subjectDhModulus = subjectDhModulus;
    }

    public BigInteger getSubjectDhGenerator() {
        return subjectDhGenerator;
    }

    public void setSubjectDhGenerator(BigInteger subjectDhGenerator) {
        this.subjectDhGenerator = subjectDhGenerator;
    }

    public List<Pair<X500AttributeType, String>> getSubject() {
        return subject;
    }

    public void setSubject(List<Pair<X500AttributeType, String>> subject) {
        this.subject = subject;
    }

    public BigInteger getSubjectRsaPrivateKey() {
        return subjectRsaPrivateKey;
    }

    public void setSubjectRsaPrivateKey(BigInteger subjectRsaPrivateKey) {
        this.subjectRsaPrivateKey = subjectRsaPrivateKey;
    }

    public BigInteger getSubjectRsaModulus() {
        return subjectRsaModulus;
    }

    public void setSubjectRsaModulus(BigInteger subjectRsaModulus) {
        this.subjectRsaModulus = subjectRsaModulus;
    }

    public BigInteger getSubjectDsaPublicKeyY() {
        return subjectDsaPublicKeyY;
    }

    public void setSubjectDsaPublicKeyY(BigInteger subjectDsaPublicKeyY) {
        this.subjectDsaPublicKeyY = subjectDsaPublicKeyY;
    }

    public BigInteger getSubjectDsaPrivateKey() {
        return subjectDsaPrivateKey;
    }

    public void setSubjectDsaPrivateKey(BigInteger subjectDsaPrivateKey) {
        this.subjectDsaPrivateKey = subjectDsaPrivateKey;
    }

    public BigInteger getSubjectEcPrivateKey() {
        return subjectEcPrivateKey;
    }

    public void setSubjectEcPrivateKey(BigInteger subjectEcPrivateKey) {
        this.subjectEcPrivateKey = subjectEcPrivateKey;
    }

    public BigInteger getSubjectDhPublicKey() {
        return subjectDhPublicKey;
    }

    public void setSubjectDhPublicKey(BigInteger subjectDhPublicKey) {
        this.subjectDhPublicKey = subjectDhPublicKey;
    }

    public X509NamedCurve getIssuerNamedCurve() {
        return issuerNamedCurve;
    }

    public void setIssuerNamedCurve(X509NamedCurve issuerNamedCurve) {
        this.issuerNamedCurve = issuerNamedCurve;
    }

    public X509NamedCurve getSubjectNamedCurve() {
        return subjectNamedCurve;
    }

    public void setSubjectNamedCurve(X509NamedCurve subjectNamedCurve) {
        this.subjectNamedCurve = subjectNamedCurve;
    }

    public BigInteger getIssuerDsaPublicKeyY() {
        return issuerDsaPublicKeyY;
    }

    public void setIssuerDsaPublicKeyY(BigInteger issuerDsaPublicKeyY) {
        this.issuerDsaPublicKeyY = issuerDsaPublicKeyY;
    }

    public X509PublicKeyType getSubjectPublicKeyType() {
        return subjectPublicKeyType;
    }

    public void setSubjectPublicKeyType(X509PublicKeyType subjectPublicKeyType) {
        this.subjectPublicKeyType = subjectPublicKeyType;
    }

    public X509SignatureAlgorithm getSubjectSignatureAlgorithm() {
        return subjectSignatureAlgorithm;
    }

    public void setSubjectSignatureAlgorithm(X509SignatureAlgorithm subjectSignatureAlgorithm) {
        this.subjectSignatureAlgorithm = subjectSignatureAlgorithm;
    }

    public BigInteger getIssuerRsaPrivateKey() {
        return issuerRsaPrivateKey;
    }

    public void setIssuerRsaPrivateKey(BigInteger issuerRsaPrivateKey) {
        this.issuerRsaPrivateKey = issuerRsaPrivateKey;
    }

    public BigInteger getIssuerRsaModulus() {
        return issuerRsaModulus;
    }

    public void setIssuerRsaModulus(BigInteger issuerRsaModulus) {
        this.issuerRsaModulus = issuerRsaModulus;
    }

    public BigInteger getIssuerDsaPrivateKey() {
        return issuerDsaPrivateKey;
    }

    public void setIssuerDsaPrivateKey(BigInteger issuerDsaPrivateKey) {
        this.issuerDsaPrivateKey = issuerDsaPrivateKey;
    }

    public BigInteger getIssuerEcPrivateKey() {
        return issuerEcPrivateKey;
    }

    public void setIssuerEcPrivateKey(BigInteger issuerEcPrivateKey) {
        this.issuerEcPrivateKey = issuerEcPrivateKey;
    }

    public List<Pair<X500AttributeType, String>> getIssuer() {
        return issuer;
    }

    public void setIssuer(List<Pair<X500AttributeType, String>> issuer) {
        this.issuer = issuer;
    }

    public byte[] getIssuerUniqueId() {
        if (issuerUniqueId != null) {
            return Arrays.copyOf(issuerUniqueId, issuerUniqueId.length);
        } else {
            return null;
        }
    }

    public void setIssuerUniqueId(byte[] issuerUniqueId) {
        this.issuerUniqueId = Arrays.copyOf(issuerUniqueId, issuerUniqueId.length);
    }

    public X509PublicKeyType getIssuerPublicKeyType() {
        return issuerPublicKeyType;
    }

    public void setIssuerPublicKeyType(X509PublicKeyType issuerPublicKeyType) {
        this.issuerPublicKeyType = issuerPublicKeyType;
    }

    public Point getSubjectEcPublicKey() {
        return subjectEcPublicKey;
    }

    public void setSubjectEcPublicKey(Point subjectEcPublicKey) {
        this.subjectEcPublicKey = subjectEcPublicKey;
    }

    public BigInteger getSubjectRsaPublicExponent() {
        return subjectRsaPublicExponent;
    }

    public void setSubjectRsaPublicExponent(BigInteger subjectRsaPublicExponent) {
        this.subjectRsaPublicExponent = subjectRsaPublicExponent;
    }
}
