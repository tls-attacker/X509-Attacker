package de.rub.nds.x509attacker.config;

import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.constants.X509Version;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import java.math.BigInteger;
import java.util.Date;

public class X509CertificateConfig {

    private X509SignatureAlgorithm signatureAlgorithm;

    private X509Version version;

    private byte[] serialNumber;

    private String issuer; //TODO this should not be a string

    private String subject; //TODO this should not be a string

    private Date notBefore;

    private Date notAfter;

    private boolean includeIssuerUniqueId;

    private boolean includeSubjectUniqueId;

    private boolean includeExtensions;

    private X509PublicKeyType publicKeyType;

    private BigInteger rsaModular;
    
    private BigInteger rsaPrivateKey;

    private BigInteger dsaPrivateKey;

    private BigInteger ecPrivateKey;

    public X509CertificateConfig() {
    }

    public BigInteger getRsaModular() {
        return rsaModular;
    }

    public void setRsaModular(BigInteger rsaModular) {
        this.rsaModular = rsaModular;
    }

    public X509SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(X509SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public X509Version getVersion() {
        return version;
    }

    public void setVersion(X509Version version) {
        this.version = version;
    }

    public byte[] getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(byte[] serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public Date getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(Date notBefore) {
        this.notBefore = notBefore;
    }

    public Date getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(Date notAfter) {
        this.notAfter = notAfter;
    }

    public boolean isIncludeIssuerUniqueId() {
        return includeIssuerUniqueId;
    }

    public void setIncludeIssuerUniqueId(boolean includeIssuerUniqueId) {
        this.includeIssuerUniqueId = includeIssuerUniqueId;
    }

    public boolean isIncludeSubjectUniqueId() {
        return includeSubjectUniqueId;
    }

    public void setIncludeSubjectUniqueId(boolean includeSubjectUniqueId) {
        this.includeSubjectUniqueId = includeSubjectUniqueId;
    }

    public boolean isIncludeExtensions() {
        return includeExtensions;
    }

    public void setIncludeExtensions(boolean includeExtensions) {
        this.includeExtensions = includeExtensions;
    }

    public X509PublicKeyType getPublicKeyType() {
        return publicKeyType;
    }

    public void setPublicKeyType(X509PublicKeyType publicKeyType) {
        this.publicKeyType = publicKeyType;
    }

    public BigInteger getRsaPrivateKey() {
        return rsaPrivateKey;
    }

    public void setRsaPrivateKey(BigInteger rsaPrivateKey) {
        this.rsaPrivateKey = rsaPrivateKey;
    }

    public BigInteger getDsaPrivateKey() {
        return dsaPrivateKey;
    }

    public void setDsaPrivateKey(BigInteger dsaPrivateKey) {
        this.dsaPrivateKey = dsaPrivateKey;
    }

    public BigInteger getEcPrivateKey() {
        return ecPrivateKey;
    }

    public void setEcPrivateKey(BigInteger ecPrivateKey) {
        this.ecPrivateKey = ecPrivateKey;
    }

}
