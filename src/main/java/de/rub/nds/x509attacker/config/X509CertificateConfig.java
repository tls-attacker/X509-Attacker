/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.config;

import de.rub.nds.asn1.constants.TimeAccurracy;
import de.rub.nds.x509attacker.constants.ValidityEncoding;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.constants.X509Version;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import java.math.BigInteger;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.joda.time.DateTime;

public class X509CertificateConfig {

    private X509SignatureAlgorithm signatureAlgorithm = X509SignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION;

    private X509Version version = X509Version.V3;

    private BigInteger serialNumber = new BigInteger("FFFFFFFFFFFFFFFF", 16);

    private List<Pair<X500AttributeType, String>> issuer;

    private List<Pair<X500AttributeType, String>> subject;

    private DateTime notBefore = new DateTime(1640980800l); // 1.1.2022

    private TimeAccurracy notBeforeAccurracy = TimeAccurracy.SECONDS;

    private ValidityEncoding defaultNotBeforeEncoding = ValidityEncoding.GENERALIZED_TIME_UTC;

    private DateTime notAfter = new DateTime(1704052800l); // 1.1.2024

    private TimeAccurracy notAfterAccurracy = TimeAccurracy.SECONDS;

    private ValidityEncoding defaultNotAfterEncoding = ValidityEncoding.GENERALIZED_TIME_UTC;

    private int timezoneOffsetInMinutes = 0;

    private boolean includeIssuerUniqueId = true;

    private boolean includeSubjectUniqueId = true;

    private boolean includeExtensions = true;

    private X509PublicKeyType publicKeyType;

    private BigInteger rsaModulus;

    private BigInteger rsaPrivateKey;

    private BigInteger dsaPrivateKey;

    private BigInteger ecPrivateKey;

    private Boolean includeDhValidationParameters = false;

    public X509CertificateConfig() {
        issuer = new LinkedList<>();
        issuer.add(new ImmutablePair<>(X500AttributeType.COMMON_NAME, "Attacker CA - Global Insecurity Provider"));
        issuer.add(new ImmutablePair<>(X500AttributeType.COUNTRY_NAME, "Global"));
        issuer.add(new ImmutablePair<>(X500AttributeType.ORGANISATION_NAME, "TLS-Attacker"));
        subject = new LinkedList<>();
        issuer.add(new ImmutablePair<>(X500AttributeType.COMMON_NAME, "tls-attacker.com"));
        issuer.add(new ImmutablePair<>(X500AttributeType.ORGANISATION_NAME, "TLS-Attacker"));
    }

    public Boolean getIncludeDhValidationParameters() {
        return includeDhValidationParameters;
    }

    public void setIncludeDhValidationParameters(Boolean includeDhValidationParameters) {
        this.includeDhValidationParameters = includeDhValidationParameters;
    }

    public int getTimezoneOffsetInMinutes() {
        return timezoneOffsetInMinutes;
    }

    public void setTimezoneOffsetInMinutes(int timezoneOffsetInMinutes) {
        this.timezoneOffsetInMinutes = timezoneOffsetInMinutes;
    }

    public void setNotBeforeAccurracy(TimeAccurracy notBeforeAccurracy) {
        this.notBeforeAccurracy = notBeforeAccurracy;
    }

    public void setNotAfterAccurracy(TimeAccurracy notAfterAccurracy) {
        this.notAfterAccurracy = notAfterAccurracy;
    }

    public TimeAccurracy getNotBeforeAccurracy() {
        return notBeforeAccurracy;
    }

    public TimeAccurracy getNotAfterAccurracy() {
        return notAfterAccurracy;
    }

    public ValidityEncoding getDefaultNotBeforeEncoding() {
        return defaultNotBeforeEncoding;
    }

    public void setDefaultNotBeforeEncoding(ValidityEncoding defaultNotBeforeEncoding) {
        this.defaultNotBeforeEncoding = defaultNotBeforeEncoding;
    }

    public ValidityEncoding getDefaultNotAfterEncoding() {
        return defaultNotAfterEncoding;
    }

    public void setDefaultNotAfterEncoding(ValidityEncoding defaultNotAfterEncoding) {
        this.defaultNotAfterEncoding = defaultNotAfterEncoding;
    }

    public BigInteger getRsaModulus() {
        return rsaModulus;
    }

    public void setRsaModulus(BigInteger rsaModulus) {
        this.rsaModulus = rsaModulus;
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

    public BigInteger getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
    }

    public List<Pair<X500AttributeType, String>> getIssuer() {
        return Collections.unmodifiableList(issuer);
    }

    public void setIssuer(List<Pair<X500AttributeType, String>> issuer) {
        this.issuer = issuer;
    }

    public List<Pair<X500AttributeType, String>> getSubject() {
        return Collections.unmodifiableList(subject);
    }

    public void setSubject(List<Pair<X500AttributeType, String>> subject) {
        this.subject = subject;
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
