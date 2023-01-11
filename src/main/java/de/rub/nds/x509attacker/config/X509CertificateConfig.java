/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.config;

import de.rub.nds.asn1.constants.TimeAccurracy;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.x509attacker.constants.ValidityEncoding;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.constants.X509Version;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

public class X509CertificateConfig {

    private X509SignatureAlgorithm signatureAlgorithm =
            X509SignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION;

    private X509Version version = X509Version.V3;

    private BigInteger serialNumber =
            new BigInteger("1122334455667788990000998877665544332211", 16);

    private List<Pair<X500AttributeType, String>> defaultIssuer;

    private List<Pair<X500AttributeType, String>> subject;

    private DateTime notBefore =
            new DateTime(2022, 1, 1, 0, 0, DateTimeZone.forID("UTC")); // 1.1.2022

    private TimeAccurracy notBeforeAccurracy = TimeAccurracy.SECONDS;

    private ValidityEncoding defaultNotBeforeEncoding = ValidityEncoding.GENERALIZED_TIME_UTC;

    private DateTime notAfter =
            new DateTime(2024, 1, 1, 0, 0, DateTimeZone.forID("UTC")); // 1.1.2024

    private TimeAccurracy notAfterAccurracy = TimeAccurracy.SECONDS;

    private ValidityEncoding defaultNotAfterEncoding = ValidityEncoding.GENERALIZED_TIME_UTC;

    private int timezoneOffsetInMinutes = 0;

    private byte[] defaultIssuerUniqueId = new byte[16];

    private byte[] subjectUniqueId = new byte[16];

    private boolean includeIssuerUniqueId = false;

    private boolean includeSubjectUniqueId = false;

    private boolean includeExtensions = false;

    private X509PublicKeyType publicKeyType = X509PublicKeyType.RSA;

    private X509PublicKeyType defaultIssuerPublicKeyType = X509PublicKeyType.RSA;

    private BigInteger rsaModulus =
            new BigInteger(
                    "00c8820d6c3ce84c8430f6835abfc7d7a912e1664f44578751f376501a8c68476c3072d919c5d39bd0dbe080e71db83bd4ab2f2f9bde3dffb0080f510a5f6929c196551f2b3c369be051054c877573195558fd282035934dc86edab8d4b1b7f555e5b2fee7275384a756ef86cb86793b5d1333f0973203cb96966766e655cd2cccae1940e4494b8e9fb5279593b75afd0b378243e51a88f6eb88def522a8cd5c6c082286a04269a2879760fcba45005d7f2672dd228809d47274f0fe0ea5531c2bd95366c05bf69edc0f3c3189866edca0c57adcca93250ae78d9eaca0393a95ff9952fc47fb7679dd3803e6a7a6fa771861e3d99e4b551a4084668b111b7eef7d",
                    16);

    private BigInteger defaultIssuerRsaModulus =
            new BigInteger(
                    "00c8820d6c3ce84c8430f6835abfc7d7a912e1664f44578751f376501a8c68476c3072d919c5d39bd0dbe080e71db83bd4ab2f2f9bde3dffb0080f510a5f6929c196551f2b3c369be051054c877573195558fd282035934dc86edab8d4b1b7f555e5b2fee7275384a756ef86cb86793b5d1333f0973203cb96966766e655cd2cccae1940e4494b8e9fb5279593b75afd0b378243e51a88f6eb88def522a8cd5c6c082286a04269a2879760fcba45005d7f2672dd228809d47274f0fe0ea5531c2bd95366c05bf69edc0f3c3189866edca0c57adcca93250ae78d9eaca0393a95ff9952fc47fb7679dd3803e6a7a6fa771861e3d99e4b551a4084668b111b7eef7d",
                    16);

    private BigInteger rsaPrivateKey =
            new BigInteger(
                    "7dc0cb485a3edb56811aeab12cdcda8e48b023298dd453a37b4d75d9e0bbba27c98f0e4852c16fd52341ffb673f64b580b7111abf14bf323e53a2dfa92727364ddb34f541f74a478a077f15277c013606aea839307e6f5fec23fdd72506feea7cbe362697949b145fe8945823a39a898ac6583fc5fbaefa1e77cbc95b3b475e66106e92b906bdbb214b87bcc94020f317fc1c056c834e9cee0ad21951fbdca088274c4ef9d8c2004c6294f49b370fb249c1e2431fb80ce5d3dc9e342914501ef4c162e54e1ee4fed9369b82afc00821a29f4979a647e60935420d44184d98f9cb75122fb604642c6d1ff2b3a51dc32eefdc57d9a9407ad6a06d10e83e2965481",
                    16);

    private BigInteger rsaPublicKey = new BigInteger("65537", 10);

    private BigInteger defaultIssuerRsaPublicKey = new BigInteger("65537", 10);

    private BigInteger dsaPublicKeyY =
            new BigInteger(
                    1,
                    ArrayConverter.hexStringToByteArray(
                            "3c991ffbb26fce963dae6540ce45904079c50398b0c32fa8485ada51dd9614e150bc8983ab6996ce4d7f8237aeeef9ec97a10e6c0949417b8412cc5711a8482f540d6b030da4e1ed591c152062775e61e6fef897c3b12a38185c12d8feddbe85298dc41324b2450d83e3b90a419373380b60ee1ca9094437c0be19fb73184726"));

    private BigInteger defaultIssuerDsaPublicKeyY =
            new BigInteger(
                    1,
                    ArrayConverter.hexStringToByteArray(
                            "3c991ffbb26fce963dae6540ce45904079c50398b0c32fa8485ada51dd9614e150bc8983ab6996ce4d7f8237aeeef9ec97a10e6c0949417b8412cc5711a8482f540d6b030da4e1ed591c152062775e61e6fef897c3b12a38185c12d8feddbe85298dc41324b2450d83e3b90a419373380b60ee1ca9094437c0be19fb73184726"));

    private BigInteger dsaPrivateKey = new BigInteger("FFFF", 16);

    private BigInteger ecPrivateKey = new BigInteger("03", 16);

    private BigInteger defaultIssuerRsaPrivateKey =
            new BigInteger(
                    "7dc0cb485a3edb56811aeab12cdcda8e48b023298dd453a37b4d75d9e0bbba27c98f0e4852c16fd52341ffb673f64b580b7111abf14bf323e53a2dfa92727364ddb34f541f74a478a077f15277c013606aea839307e6f5fec23fdd72506feea7cbe362697949b145fe8945823a39a898ac6583fc5fbaefa1e77cbc95b3b475e66106e92b906bdbb214b87bcc94020f317fc1c056c834e9cee0ad21951fbdca088274c4ef9d8c2004c6294f49b370fb249c1e2431fb80ce5d3dc9e342914501ef4c162e54e1ee4fed9369b82afc00821a29f4979a647e60935420d44184d98f9cb75122fb604642c6d1ff2b3a51dc32eefdc57d9a9407ad6a06d10e83e2965481",
                    16);

    private BigInteger defaultIssuerDsaPrivateKey = new BigInteger("FFFF", 16);

    private BigInteger defaultIssuerEcPrivateKey = new BigInteger("03", 16);

    private Boolean includeDhValidationParameters = false;

    private X509NamedCurve defaultSubjectNamedCurve = X509NamedCurve.SECP256R1;

    public X509CertificateConfig() {
        defaultIssuer = new LinkedList<>();
        defaultIssuer.add(
                new ImmutablePair<>(
                        X500AttributeType.COMMON_NAME, "Attacker CA - Global Insecurity Provider"));
        defaultIssuer.add(new ImmutablePair<>(X500AttributeType.COUNTRY_NAME, "Global"));
        defaultIssuer.add(new ImmutablePair<>(X500AttributeType.ORGANISATION_NAME, "TLS-Attacker"));
        subject = new LinkedList<>();
        subject.add(new ImmutablePair<>(X500AttributeType.COMMON_NAME, "tls-attacker.com"));
        subject.add(new ImmutablePair<>(X500AttributeType.ORGANISATION_NAME, "TLS-Attacker"));
    }

    public X509NamedCurve getDefaultSubjectNamedCurve() {
        return defaultSubjectNamedCurve;
    }

    public void setDefaultSubjectNamedCurve(X509NamedCurve defaultSubjectNamedCurve) {
        this.defaultSubjectNamedCurve = defaultSubjectNamedCurve;
    }

    public BigInteger getDsaPublicKeyY() {
        return dsaPublicKeyY;
    }

    public void setDsaPublicKeyY(BigInteger dsaPublicKeyY) {
        this.dsaPublicKeyY = dsaPublicKeyY;
    }

    public BigInteger getDefaultIssuerDsaPublicKeyY() {
        return defaultIssuerDsaPublicKeyY;
    }

    public void setDefaultIssuerDsaPublicKeyY(BigInteger defaultIssuerDsaPublicKeyY) {
        this.defaultIssuerDsaPublicKeyY = defaultIssuerDsaPublicKeyY;
    }

    public X509PublicKeyType getDefaultIssuerPublicKeyType() {
        return defaultIssuerPublicKeyType;
    }

    public void setDefaultIssuerPublicKeyType(X509PublicKeyType defaultIssuerPublicKeyType) {
        this.defaultIssuerPublicKeyType = defaultIssuerPublicKeyType;
    }

    public BigInteger getDefaultIssuerRsaPublicKey() {
        return defaultIssuerRsaPublicKey;
    }

    public void setDefaultIssuerRsaPublicKey(BigInteger defaultIssuerRsaPublicKey) {
        this.defaultIssuerRsaPublicKey = defaultIssuerRsaPublicKey;
    }

    public BigInteger getDefaultIssuerRsaModulus() {
        return defaultIssuerRsaModulus;
    }

    public void setDefaultIssuerRsaModulus(BigInteger defaultIssuerRsaModulus) {
        this.defaultIssuerRsaModulus = defaultIssuerRsaModulus;
    }

    public BigInteger getDefaultIssuerRsaPrivateKey() {
        return defaultIssuerRsaPrivateKey;
    }

    public void setDefaultIssuerRsaPrivateKey(BigInteger defaultIssuerRsaPrivateKey) {
        this.defaultIssuerRsaPrivateKey = defaultIssuerRsaPrivateKey;
    }

    public BigInteger getDefaultIssuerDsaPrivateKey() {
        return defaultIssuerDsaPrivateKey;
    }

    public void setDefaultIssuerDsaPrivateKey(BigInteger defaultIssuerDsaPrivateKey) {
        this.defaultIssuerDsaPrivateKey = defaultIssuerDsaPrivateKey;
    }

    public BigInteger getDefaultIssuerEcPrivateKey() {
        return defaultIssuerEcPrivateKey;
    }

    public void setDefaultIssuerEcPrivateKey(BigInteger defaultIssuerEcPrivateKey) {
        this.defaultIssuerEcPrivateKey = defaultIssuerEcPrivateKey;
    }

    public BigInteger getRsaPublicKey() {
        return rsaPublicKey;
    }

    public void setRsaPublicKey(BigInteger rsaPublicKey) {
        this.rsaPublicKey = rsaPublicKey;
    }

    public byte[] getDefaultIssuerUniqueId() {
        return Arrays.copyOf(defaultIssuerUniqueId, defaultIssuerUniqueId.length);
    }

    public void setDefaultIssuerUniqueId(byte[] defaultIssuerUniqueId) {
        this.defaultIssuerUniqueId =
                Arrays.copyOf(defaultIssuerUniqueId, defaultIssuerUniqueId.length);
    }

    public byte[] getSubjectUniqueId() {
        return Arrays.copyOf(subjectUniqueId, subjectUniqueId.length);
    }

    public void setSubjectUniqueId(byte[] subjectUniqueId) {
        this.subjectUniqueId = Arrays.copyOf(subjectUniqueId, subjectUniqueId.length);
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

    public X509SignatureAlgorithm getDefaultSignatureAlgorithm() {
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

    public List<Pair<X500AttributeType, String>> getDefaultIssuer() {
        return Collections.unmodifiableList(defaultIssuer);
    }

    public void setDefaultIssuer(List<Pair<X500AttributeType, String>> defaultIssuer) {
        this.defaultIssuer = defaultIssuer;
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
