/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.config;

import de.rub.nds.asn1.constants.TimeAccurracy;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.protocol.constants.PointFormat;
import de.rub.nds.protocol.crypto.ec.EllipticCurve;
import de.rub.nds.protocol.crypto.ec.Point;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509attacker.constants.ValidityEncoding;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.constants.X509Version;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.xml.bind.annotation.XmlRootElement;
import jakarta.xml.bind.annotation.XmlSeeAlso;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.io.Serializable;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

@XmlRootElement
@XmlSeeAlso({X500AttributeType.class})
@XmlAccessorType(XmlAccessType.FIELD)
public class X509CertificateConfig implements Serializable {

    private X509SignatureAlgorithm signatureAlgorithm =
            X509SignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION;

    private X509Version version = X509Version.V3;

    private BigInteger serialNumber =
            new BigInteger("1122334455667788990000998877665544332211", 16);

    @XmlElement(name = "attributeField")
    @XmlElementWrapper
    private List<Pair<X500AttributeType, String>> defaultIssuer;

    @XmlElement(name = "attributeField")
    @XmlElementWrapper
    private List<Pair<X500AttributeType, String>> subject;

    private DateTime notBefore =
            new DateTime(2024, 1, 1, 0, 0, DateTimeZone.forID("UTC")); // 1.1.2022

    private TimeAccurracy notBeforeAccurracy = TimeAccurracy.SECONDS;

    private ValidityEncoding defaultNotBeforeEncoding = ValidityEncoding.UTC;

    private DateTime notAfter =
            new DateTime(2026, 1, 1, 0, 0, DateTimeZone.forID("UTC")); // 1.1.2024

    private TimeAccurracy notAfterAccurracy = TimeAccurracy.SECONDS;

    private ValidityEncoding defaultNotAfterEncoding = ValidityEncoding.UTC;

    private int timezoneOffsetInMinutes = 0;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] defaultIssuerUniqueId = new byte[16];

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
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

    private BigInteger defaultIssuerDsaNonce = new BigInteger("FFFF", 16);

    private BigInteger ecPrivateKey = new BigInteger("03", 16);

    private Point ecPublicKey = null;

    private BigInteger dhPublicKey =
            new BigInteger(
                    "1681394322319870210256248147442054090932206341802045994096983595338955005659597889438844944973091109169386672405121543637145770529429523265430428939872512403174385178481044046136308211908145326150862942095901388094689735302782989849547006782152416065835917754524128066855629604432863944505368952435189013827076830989854538865748983542800796757528564177346424878006955949578358387831947980868631465396755299911740286746985618037131874030946232884477317882584267555644379683318311870146325925229513591635876430792601613210014121996948225527455402441560525635353922285085761971017215783615516067426987857987615552181753413366146711059912603872042407074785495470158193264812602138742855102015514259595799563627587494141294808352489803063037527687040198681542610119643356864513310181906089192764607252393357066541271957444400155509140577926505949412459365574565915486318740613353374655472464297513587327510443326824815201405655725",
                    10);

    /**
     * The dh private key is intentionally chosen to not be super small such that even when the
     * generator is small and the modulus is big one cannot tell immediately that the private key
     * was super small
     */
    private BigInteger dhPrivateKey =
            new BigInteger("D0EC4E50BB290A42E9E355C73D8809345DE2E139", 16);

    private BigInteger dhModulus =
            new BigInteger(
                    "5809605995369958062791915965639201402176612226902900533702900882779736177890990861472094774477339581147373410185646378328043729800750470098210924487866935059164371588168047540943981644516632755067501626434556398193186628990071248660819361205119793693985433297036118232914410171876807536457391277857011849897410207519105333355801121109356897459426271845471397952675959440793493071628394122780510124618488232602464649876850458861245784240929258426287699705312584509625419513463605155428017165714465363094021609290561084025893662561222573202082865797821865270991145082200656978177192827024538990239969175546190770645685893438011714430426409338676314743571154537142031573004276428701433036381801705308659830751190352946025482059931306571004727362479688415574702596946457770284148435989129632853918392117997472632693078113129886487399347796982772784615865232621289656944284216824611318709764535152507354116344703769998514148343807",
                    10);

    private BigInteger dhGenerator = new BigInteger("02", 16);

    private BigInteger dsaPrimeP =
            new BigInteger(
                    1,
                    ArrayConverter.hexStringToByteArray(
                            "E0A67598CD1B763BC98C8ABB333E5DDA0CD3AA0E5E1FB5BA8A7B4EABC10BA338FAE06DD4B90FDA70D7CF0CB0C638BE3341BEC0AF8A7330A3307DED2299A0EE606DF035177A239C34A912C202AA5F83B9C4A7CF0235B5316BFC6EFB9A248411258B30B839AF172440F32563056CB67A861158DDD90E6A894C72A5BBEF9E286C6B"));

    private BigInteger dsaPrimeQ =
            new BigInteger(
                    1,
                    ArrayConverter.hexStringToByteArray(
                            "E950511EAB424B9A19A2AEB4E159B7844C589C4F"));

    private BigInteger dsaGenerator =
            new BigInteger(
                    1,
                    ArrayConverter.hexStringToByteArray(
                            "D29D5121B0423C2769AB21843E5A3240FF19CACC792264E3BB6BE4F78EDD1B15C4DFF7F1D905431F0AB16790E1F773B5CE01C804E509066A9919F5195F4ABC58189FD9FF987389CB5BEDF21B4DAB4F8B76A055FFE2770988FE2EC2DE11AD92219F0B351869AC24DA3D7BA87011A701CE8EE7BFE49486ED4527B7186CA4610A75"));

    private BigInteger defaultIssuerRsaPrivateKey =
            new BigInteger(
                    "7dc0cb485a3edb56811aeab12cdcda8e48b023298dd453a37b4d75d9e0bbba27c98f0e4852c16fd52341ffb673f64b580b7111abf14bf323e53a2dfa92727364ddb34f541f74a478a077f15277c013606aea839307e6f5fec23fdd72506feea7cbe362697949b145fe8945823a39a898ac6583fc5fbaefa1e77cbc95b3b475e66106e92b906bdbb214b87bcc94020f317fc1c056c834e9cee0ad21951fbdca088274c4ef9d8c2004c6294f49b370fb249c1e2431fb80ce5d3dc9e342914501ef4c162e54e1ee4fed9369b82afc00821a29f4979a647e60935420d44184d98f9cb75122fb604642c6d1ff2b3a51dc32eefdc57d9a9407ad6a06d10e83e2965481",
                    16);

    private BigInteger defaultIssuerDsaPrivateKey =
            new BigInteger("D0EC4E50BB290A42E9E355C73D8809345DE2E139", 16);

    private BigInteger defaultIssuerEcPrivateKey = new BigInteger("03", 16);

    private BigInteger defaultIssuerNonce = new BigInteger("ABCDEF", 16);

    private Boolean includeDhValidationParameters = false;

    private X509NamedCurve defaultSubjectNamedCurve = X509NamedCurve.SECP256R1;

    private X509NamedCurve defaultIssuerNamedCurve = X509NamedCurve.SECP256R1;

    private BigInteger dhValidationParameterPgenCounter = new BigInteger("1");

    private byte[] dhValidationParameterSeed = new byte[32];

    private PointFormat defaultEcPointFormat = PointFormat.UNCOMPRESSED;

    public X509CertificateConfig() {
        defaultIssuer = new LinkedList<>();
        defaultIssuer.add(
                new Pair<>(
                        X500AttributeType.COMMON_NAME, "Attacker CA - Global Insecurity Provider"));
        defaultIssuer.add(new Pair<>(X500AttributeType.COUNTRY_NAME, "Global"));
        defaultIssuer.add(new Pair<>(X500AttributeType.ORGANISATION_NAME, "TLS-Attacker"));
        subject = new LinkedList<>();
        subject.add(new Pair<>(X500AttributeType.COMMON_NAME, "tls-attacker.com"));
        subject.add(new Pair<>(X500AttributeType.ORGANISATION_NAME, "TLS-Attacker"));
        EllipticCurve curve = defaultSubjectNamedCurve.getParameters().getGroup();
        // Hardcoded public key, fitting to the default values (SECP256R1 with k=3)
        ecPublicKey =
                curve.getPoint(
                        new BigInteger(
                                "42877656971275811310262564894490210024759287182177196162425349131675946712428"),
                        new BigInteger(
                                "61154801112014214504178281461992570017247172004704277041681093927569603776562"));
    }

    public BigInteger getDefaultIssuerDsaNonce() {
        return defaultIssuerDsaNonce;
    }

    public void setDefaultIssuerDsaNonce(BigInteger defaultIssuerDsaNonc) {
        this.defaultIssuerDsaNonce = defaultIssuerDsaNonc;
    }

    public X509NamedCurve getDefaultIssuerNamedCurve() {
        return defaultIssuerNamedCurve;
    }

    public void setDefaultIssuerNamedCurve(X509NamedCurve defaultIssuerNamedCurve) {
        this.defaultIssuerNamedCurve = defaultIssuerNamedCurve;
    }

    public BigInteger getDefaultIssuerNonce() {
        return defaultIssuerNonce;
    }

    public void setDefaultIssuerNonce(BigInteger defaultIssuerNonce) {
        this.defaultIssuerNonce = defaultIssuerNonce;
    }

    public PointFormat getDefaultEcPointFormat() {
        return defaultEcPointFormat;
    }

    public void setDefaultEcPointFormat(PointFormat defaultEcPointFormat) {
        this.defaultEcPointFormat = defaultEcPointFormat;
    }

    public BigInteger getDhValidationParameterPgenCounter() {
        return dhValidationParameterPgenCounter;
    }

    public void setDhValidationParameterPgenCounter(BigInteger dhValidationParameterPgenCounter) {
        this.dhValidationParameterPgenCounter = dhValidationParameterPgenCounter;
    }

    public byte[] getDhValidationParameterSeed() {
        return dhValidationParameterSeed;
    }

    public void setDhValidationParameterSeed(byte[] seed) {
        this.dhValidationParameterSeed = seed;
    }

    public BigInteger getDsaPrimeP() {
        return dsaPrimeP;
    }

    public void setDsaPrimeP(BigInteger dsaPrimeP) {
        this.dsaPrimeP = dsaPrimeP;
    }

    public BigInteger getDsaPrimeQ() {
        return dsaPrimeQ;
    }

    public void setDsaPrimeQ(BigInteger dsaPrimeQ) {
        this.dsaPrimeQ = dsaPrimeQ;
    }

    public BigInteger getDsaGenerator() {
        return dsaGenerator;
    }

    public void setDsaGenerator(BigInteger dsaGenerator) {
        this.dsaGenerator = dsaGenerator;
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

    public BigInteger getRsaPublicExponent() {
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

    public void setIssuer(List<Pair<X500AttributeType, String>> defaultIssuer) {
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

    public BigInteger getDhPrivateKey() {
        return dhPrivateKey;
    }

    public void setDhPrivateKey(BigInteger dhPrivateKey) {
        this.dhPrivateKey = dhPrivateKey;
    }

    public BigInteger getDhModulus() {
        return dhModulus;
    }

    public void setDhModulus(BigInteger dhModulus) {
        this.dhModulus = dhModulus;
    }

    public BigInteger getDhGenerator() {
        return dhGenerator;
    }

    public void setDhGenerator(BigInteger dhGenerator) {
        this.dhGenerator = dhGenerator;
    }

    public Point getEcPublicKey() {
        return ecPublicKey;
    }

    public void setEcPublicKey(Point ecPublicKey) {
        this.ecPublicKey = ecPublicKey;
    }

    public BigInteger getDhPublicKey() {
        return dhPublicKey;
    }

    public void setDhPublicKey(BigInteger dhPublicKey) {
        this.dhPublicKey = dhPublicKey;
    }
}
