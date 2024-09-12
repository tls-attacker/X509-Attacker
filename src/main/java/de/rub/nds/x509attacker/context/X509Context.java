/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.context;

import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.constants.X509Version;
import java.math.BigInteger;
import java.util.List;
import org.joda.time.DateTime;

public class X509Context {

    private BigInteger issuerRsaPrivateKey = null;

    private BigInteger issuerRsaModulus = null;

    private BigInteger issuerDsaPublicKeyY = null;

    private BigInteger issuerDsaPrivateKeyX = null;

    private BigInteger issuerDsaPrivateK = null;

    private BigInteger issuerEcPrivateKey = null;

    private X509PublicKeyType issuerPublicKeyType = null;

    private byte[] issuerUniqueId = null;

    private byte[] subjectUniqueId = null;

    private X509NamedCurve issuerNamedCurve = null;

    private List<Pair<X500AttributeType, String>> issuer = null;

    private List<Pair<X500AttributeType, String>> subject = null;

    private BigInteger subjectRsaPrivateKey = null;

    private BigInteger subjectRsaModulus = null;

    private BigInteger subjectRsaPublicExponent = null;

    private BigInteger subjectDsaPublicKeyY = null;

    private BigInteger subjectDsaPrimeModulusP = null;

    private BigInteger subjectDsaPrimeDivisorQ = null;

    private BigInteger subjectDsaGeneratorG = null;

    private BigInteger subjectDsaPrivateK = null;

    private BigInteger subjectDsaPrivateKeyX = null;

    private BigInteger subjectEcPrivateKey = null;

    private Point subjectEcPublicKey = null;

    private X509SignatureAlgorithm subjectSignatureAlgorithm;

    private X509PublicKeyType subjectPublicKeyType = null;

    private X509NamedCurve subjectNamedCurve = null;

    private BigInteger subjectDhPrivateKey = null;

    private BigInteger subjectDhPublicKey = null;

    private BigInteger subjectDhModulus = null;

    private BigInteger subjectDhGenerator = null;

    private byte[] subjectDhValidationParamsSeed = null;

    private BigInteger subjectDhValidationParamsPgen = null;

    private BigInteger serialNumber = null;

    private DateTime notBefore = null;

    private DateTime notAfter = null;

    private X509Version version = null;

    private byte[] rsaPssSalt = null;

    private HashAlgorithm rsaPssHashAlgorithm;

    private BigInteger ecdsaNonce;

    private X509CertificateConfig config;

    private X509Chooser chooser;

    public X509Context() {
        this(new X509CertificateConfig());
    }

    public X509Context(X509CertificateConfig config) {
        this.config = config;
        this.chooser = new X509Chooser(config, this);
    }

    public X509Version getVersion() {
        return version;
    }

    public void setVersion(X509Version version) {
        this.version = version;
    }

    public byte[] getRsaPssSalt() {
        return rsaPssSalt;
    }

    public void setRsaPssSalt(byte[] rsaPssSalt) {
        this.rsaPssSalt = rsaPssSalt;
    }

    public HashAlgorithm getRsaPssHashAlgorithm() {
        return rsaPssHashAlgorithm;
    }

    public void setRsaPssHashAlgorithm(HashAlgorithm rsaPssHashAlgorithm) {
        this.rsaPssHashAlgorithm = rsaPssHashAlgorithm;
    }

    public BigInteger getEcdsaNonce() {
        return ecdsaNonce;
    }

    public void setEcdsaNonce(BigInteger ecdsaNonce) {
        this.ecdsaNonce = ecdsaNonce;
    }

    public DateTime getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(DateTime notBefore) {
        this.notBefore = notBefore;
    }

    public DateTime getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(DateTime notAfter) {
        this.notAfter = notAfter;
    }

    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
    }

    public byte[] getSubjectDhValidationParamsSeed() {
        return subjectDhValidationParamsSeed;
    }

    public void setSubjectDhValidationParamsSeed(byte[] subjectDhValidationParamsSeed) {
        this.subjectDhValidationParamsSeed = subjectDhValidationParamsSeed;
    }

    public BigInteger getSubjectDhValidationParamsPgen() {
        return subjectDhValidationParamsPgen;
    }

    public void setSubjectDhValidationParamsPgen(BigInteger subjectDhValidationParamsPgen) {
        this.subjectDhValidationParamsPgen = subjectDhValidationParamsPgen;
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

    public BigInteger getSubjectDsaPrivateKeyX() {
        return subjectDsaPrivateKeyX;
    }

    public void setSubjectDsaPrivateKeyX(BigInteger subjectDsaPrivateKeyX) {
        this.subjectDsaPrivateKeyX = subjectDsaPrivateKeyX;
    }

    public BigInteger getSubjectDsaPrivateK() {
        return subjectDsaPrivateK;
    }

    public void setSubjectDsaPrivateK(BigInteger subjectDsaPrivateK) {
        this.subjectDsaPrivateK = subjectDsaPrivateK;
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

    public BigInteger getIssuerDsaPrivateKeyX() {
        return issuerDsaPrivateKeyX;
    }

    public void setIssuerDsaPrivateKeyX(BigInteger issuerDsaPrivateKeyX) {
        this.issuerDsaPrivateKeyX = issuerDsaPrivateKeyX;
    }

    public BigInteger getIssuerDsaPrivateK() {
        return issuerDsaPrivateK;
    }

    public void setIssuerDsaPrivateK(BigInteger issuerDsaPrivateK) {
        this.issuerDsaPrivateK = issuerDsaPrivateK;
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
        return issuerUniqueId;
    }

    public void setIssuerUniqueId(byte[] issuerUniqueId) {
        this.issuerUniqueId = issuerUniqueId;
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

    public byte[] getSubjectUniqueId() {
        return subjectUniqueId;
    }

    public void setSubjectUniqueId(byte[] subjectUniqueId) {
        this.subjectUniqueId = subjectUniqueId;
    }

    public BigInteger getSubjectDsaPrimeModulusP() {
        return subjectDsaPrimeModulusP;
    }

    public void setSubjectDsaPrimeModulusP(BigInteger subjectDsaPrimeModulusP) {
        this.subjectDsaPrimeModulusP = subjectDsaPrimeModulusP;
    }

    public BigInteger getSubjectDsaPrimeDivisorQ() {
        return subjectDsaPrimeDivisorQ;
    }

    public void setSubjectDsaPrimeDivisorQ(BigInteger subjectDsaPrimeDivisorQ) {
        this.subjectDsaPrimeDivisorQ = subjectDsaPrimeDivisorQ;
    }

    public BigInteger getSubjectDsaGeneratorG() {
        return subjectDsaGeneratorG;
    }

    public void setSubjectDsaGeneratorG(BigInteger subjectDsaGeneratorG) {
        this.subjectDsaGeneratorG = subjectDsaGeneratorG;
    }
}
