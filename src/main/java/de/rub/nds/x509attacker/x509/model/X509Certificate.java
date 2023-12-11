/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.asn1.model.Asn1BitString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.crypto.hash.HashCalculator;
import de.rub.nds.protocol.crypto.key.EcdhPublicKey;
import de.rub.nds.protocol.crypto.key.EcdsaPublicKey;
import de.rub.nds.protocol.crypto.key.EddsaPublicKey;
import de.rub.nds.protocol.crypto.key.PublicKeyContainer;
import de.rub.nds.protocol.crypto.signature.SignatureComputations;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.ExtendedKeyUsage;
import de.rub.nds.x509attacker.constants.KeyUsage;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.constants.X509Version;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.handler.X509CertificateHandler;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.model.publickey.PublicKeyBitString;
import de.rub.nds.x509attacker.x509.model.publickey.PublicKeyContent;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.PublicParameters;
import de.rub.nds.x509attacker.x509.parser.X509CertificateParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509CertificatePreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Certificate extends Asn1Sequence implements X509Component {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final X509SignatureAlgorithm[] WEAK_SIGNATURE_ALGORITHMS = {
        X509SignatureAlgorithm.DSA_WITH_SHA1,
        X509SignatureAlgorithm.ECDSA_WITH_SHA1,
        X509SignatureAlgorithm.MD2_WITH_RSA_ENCRYPTION,
        X509SignatureAlgorithm.MD5_WITH_RSA_ENCRYPTION,
        X509SignatureAlgorithm.MD4_WITH_RSA_ENCRYPTION,
        X509SignatureAlgorithm.SHA1_WITH_RSA_ENCRYPTION
    };

    @HoldsModifiableVariable private TbsCertificate tbsCertificate;

    @HoldsModifiableVariable
    private CertificateSignatureAlgorithmIdentifier signatureAlgorithmIdentifier;

    @HoldsModifiableVariable private Asn1BitString signature;

    @HoldsModifiableVariable private SignatureComputations signatureComputations;

    public X509Certificate(String identifier, X509CertificateConfig certificateConfig) {
        super(identifier);
        tbsCertificate = new TbsCertificate("tbsCertificate", certificateConfig);
        signatureAlgorithmIdentifier =
                new CertificateSignatureAlgorithmIdentifier("signatureAlgorithm");
        signature = new Asn1BitString("signature");
    }

    public X509Certificate(String identifier) {
        super(identifier);
        tbsCertificate = new TbsCertificate("tbsCertificate");
        signatureAlgorithmIdentifier =
                new CertificateSignatureAlgorithmIdentifier("signatureAlgorithm");
        signature = new Asn1BitString("signature");
    }

    /** Default constructor to please JAXB */
    private X509Certificate() {
        super(null);
    }

    public TbsCertificate getTbsCertificate() {
        return tbsCertificate;
    }

    public void setTbsCertificate(TbsCertificate tbsCertificate) {
        this.tbsCertificate = tbsCertificate;
    }

    public CertificateSignatureAlgorithmIdentifier getSignatureAlgorithmIdentifier() {
        return signatureAlgorithmIdentifier;
    }

    public void setSignatureAlgorithmIdentifier(
            CertificateSignatureAlgorithmIdentifier signatureAlgorithm) {
        this.signatureAlgorithmIdentifier = signatureAlgorithm;
    }

    public Asn1BitString getSignature() {
        return signature;
    }

    public void setSignature(Asn1BitString signature) {
        this.signature = signature;
    }

    public byte[] getSha256Fingerprint() {
        return HashCalculator.compute(
                this.getSerializer(new X509Chooser(new X509CertificateConfig(), new X509Context()))
                        .serialize(),
                HashAlgorithm.SHA256);
    }

    public X509PublicKeyType getCertificateKeyType() {
        return getPublicKey().getX509PublicKeyType();
    }

    public NamedEllipticCurveParameters getEllipticCurve() {
        PublicKeyContainer publicKeyContainer = getPublicKeyContainer();
        if (publicKeyContainer instanceof EcdsaPublicKey) {
            return ((EcdsaPublicKey) publicKeyContainer).getParameters();
        }
        if (publicKeyContainer instanceof EcdhPublicKey) {
            return ((EcdhPublicKey) publicKeyContainer).getParameters();
        }
        if (publicKeyContainer instanceof EddsaPublicKey) {
            return ((EddsaPublicKey) publicKeyContainer).getParameters();
        }
        LOGGER.warn("X.509 Certificate does not contain an EC PublicKey. Returning null.");
        return null;
    }

    public PublicKeyContent getPublicKey() {
        Optional<TbsCertificate> optionalTbs = Optional.ofNullable(getTbsCertificate());
        Optional<SubjectPublicKeyInfo> optionalPublicKeyType =
                optionalTbs.map(TbsCertificate::getSubjectPublicKeyInfo);
        Optional<PublicKeyBitString> publicKeyString =
                optionalPublicKeyType.map(SubjectPublicKeyInfo::getSubjectPublicKeyBitString);
        Optional<PublicKeyContent> publicKeyContentOptional =
                publicKeyString.map(PublicKeyBitString::getX509PublicKeyContent);
        return (PublicKeyContent) publicKeyContentOptional.get();
    }

    public PublicParameters getPublicParameters() {
        return getTbsCertificate().getSubjectPublicKeyInfo().getAlgorithm().getParameters();
    }

    public PublicKeyContainer getPublicKeyContainer() {
        Optional<TbsCertificate> optionalTbs = Optional.ofNullable(getTbsCertificate());
        return optionalTbs
                .map(TbsCertificate::getSubjectPublicKeyInfo)
                .get()
                .getPublicKeyContainer();
    }

    public DateTime getNotBefore() {
        return tbsCertificate.getValidity().getNotBefore().getTimeValue();
    }

    public DateTime getNotAfter() {
        return tbsCertificate.getValidity().getNotAfter().getTimeValue();
    }

    public Boolean isExpired() {
        return getNotAfter().isBeforeNow();
    }

    public Boolean isYetValid() {
        return getNotBefore().isBeforeNow();
    }

    public Boolean isRevokedCrl() {
        throw new UnsupportedOperationException("isRevokedCrl not implemented yet");
    }

    public Boolean isRevokedOcsp() {
        throw new UnsupportedOperationException("isRevokedOcsp not implemented yet");
    }

    public HashAlgorithm getHashAlgorithm() {
        ObjectIdentifier oid =
                new ObjectIdentifier(
                        getSignatureAlgorithmIdentifier().getAlgorithm().getValue().getValue());
        return X509SignatureAlgorithm.decodeFromOidBytes(oid.getEncoded()).getHashAlgorithm();
    }

    public Boolean hasWeakBlacklistedDebianKey() {
        throw new UnsupportedOperationException("hasWeakBlacklistedDebianKey not implemented yet");
    }

    /**
     * A certificate is considered a leaf by us if it either has a common name that resolves to a
     * URL or IP or a SAN extension. This is probably not enough but this is what we are doing for
     * now
     */
    public Boolean isLeaf() {
        String commonName = getCommonName();
        return commonName != null
                && isIpOrDomain(commonName); // || hasSanExtension() == Boolean.TRUE; TODO
    }

    private boolean isIpOrDomain(String input) {
        try {
            // Try to parse the input as an IP address
            InetAddress.getByName(input);

            // The input is an IP address
            return true;
        } catch (UnknownHostException e) {
            // The input is not an IP address, so try to parse it as a domain name
            try {
                InetAddress.getAllByName(input);

                // The input is a domain name
                return true;
            } catch (UnknownHostException e2) {
                // The input is not a domain name either
                return false;
            }
        }
    }

    public Boolean isValidLeafForUri(String uri) {
        if (isLeaf()) {
            // It is a leaf, now we need to check the domain name
            return isCommonNameValidForUri(uri); // TODO || isSanValidForUri(uri);
        } else {
            return false;
        }
    }

    public boolean isCommonNameValidForUri(String uri) {
        String commonName = getCommonName();
        if (commonName.startsWith("*.")) {
            // Handle wildcard certificates
            String suffix = commonName.substring(2);
            return uri.endsWith(suffix);
        } else {
            // Handle regular certificates
            return uri.equals(commonName);
        }
    }

    public boolean isSanValidForUri(String uri) {
        List<String> subjectAlternativeNames = getSubjectAlternativeNames();
        for (String name : subjectAlternativeNames) {
            if (name.startsWith("*.")) {
                // Handle wildcard certificates
                String suffix = name.substring(2);
                if (uri.endsWith(suffix)) {
                    return true;
                }
            } else {
                // Handle regular certificates
                if (uri.equals(name)) {
                    return true;
                }
            }
        }
        return false;
    }

    public String getCommonName() {
        for (RelativeDistinguishedName relativeDistinguishedName :
                getTbsCertificate().getSubject().getRelativeDistinguishedNames()) {
            for (AttributeTypeAndValue attributeTypeAndValue :
                    relativeDistinguishedName.getAttributeTypeAndValueList()) {
                if ((attributeTypeAndValue).getX500AttributeTypeFromValue()
                        == X500AttributeType.COMMON_NAME) {
                    return attributeTypeAndValue.getStringValueOfValue();
                }
            }
        }
        return null;
    }

    public List<String> getSubjectAlternativeNames() {
        throw new UnsupportedOperationException("getSubjectAlternativeNames not implemented yet");
    }

    public Boolean hasSanExtension() {
        throw new UnsupportedOperationException("hasSanExtension not implemented yet");
    }

    public Boolean hasExtendedKeyUsageExtension() {
        throw new UnsupportedOperationException("hasExtendedKeyUsageExtension not implemented yet");
    }

    public Boolean hasSignedCertificateTransparencyEntry() {
        throw new UnsupportedOperationException(
                "hasSignedCertificateTransparencyEntry not implemented yet");
    }

    public Boolean hasOcsp() {
        throw new UnsupportedOperationException("hasOcsp not implemented yet");
    }

    public Boolean hasCertificateRevocationList() {
        throw new UnsupportedOperationException("hasCertificateRevocationList not implemented yet");
    }

    public Boolean isOcspMustStaple() {
        throw new UnsupportedOperationException("isOcspMustStaple not implemented yet");
    }

    /**
     * We consider a certificate to be self signed if the issuer equals the subject
     *
     * @return
     */
    public Boolean isSelfSigned() {
        return getIssuerString().equals(getSubjectString());
    }

    private String getRdnString(List<RelativeDistinguishedName> relativeDistinguishedNames) {
        StringBuilder builder = new StringBuilder();
        for (RelativeDistinguishedName relativeDistinguishedName : relativeDistinguishedNames) {
            for (AttributeTypeAndValue attributeTypeAndValue :
                    relativeDistinguishedName.getAttributeTypeAndValueList()) {
                builder.append(attributeTypeAndValue.getStringRepresentation());
                builder.append(" ");
            }
        }
        return builder.toString();
    }

    /**
     * Returns the Subject in a String representation
     *
     * @return
     */
    public String getSubjectString() {
        return getRdnString(getTbsCertificate().getSubject().getRelativeDistinguishedNames())
                .trim();
    }

    /**
     * Returns the Subject in a String representation
     *
     * @return
     */
    public String getIssuerString() {
        return getRdnString(getTbsCertificate().getIssuer().getRelativeDistinguishedNames()).trim();
    }

    public X509Version getX509Version() {
        return tbsCertificate.getVersion().getInnerField().getVersion();
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        ObjectIdentifier oid =
                new ObjectIdentifier(
                        getSignatureAlgorithmIdentifier().getAlgorithm().getValue().getValue());
        return X509SignatureAlgorithm.decodeFromOidBytes(oid.getEncoded()).getSignatureAlgorithm();
    }

    public X509SignatureAlgorithm getX509SignatureAlgorithm() {
        ObjectIdentifier oid =
                new ObjectIdentifier(
                        getSignatureAlgorithmIdentifier().getAlgorithm().getValue().getValue());
        return X509SignatureAlgorithm.decodeFromOidBytes(oid.getEncoded());
    }

    public ObjectIdentifier getX509SignatureAlgorithmObjectIdentifier() {
        return new ObjectIdentifier(
                getSignatureAlgorithmIdentifier().getAlgorithm().getValue().getValue());
    }

    public List<KeyUsage> getKeyUsages() {
        throw new UnsupportedOperationException("getKeyUsages not implemented yet");
    }

    public List<ExtendedKeyUsage> getExtendedKeyUsages() {
        throw new UnsupportedOperationException("getExtendedKeyUsages not implemented yet");
    }

    public SignatureComputations getSignatureComputations() {
        return signatureComputations;
    }

    public void setSignatureComputations(SignatureComputations signatureComputations) {
        this.signatureComputations = signatureComputations;
    }

    public byte[] getAkid() {
        throw new UnsupportedOperationException("getAkid not implemented yet");
    }

    public byte[] getSkid() {
        throw new UnsupportedOperationException("getSkid not implemented yet");
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(getSha256Fingerprint());
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        X509Certificate other = (X509Certificate) obj;
        if (Arrays.equals(getSha256Fingerprint(), other.getSha256Fingerprint())) return true;
        return false;
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new X509CertificateHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new X509CertificateParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new X509CertificatePreparator(chooser, this);
    }

    public boolean isWeakSignature() {
        for (X509SignatureAlgorithm algorithm : WEAK_SIGNATURE_ALGORITHMS) {
            if (algorithm == getX509SignatureAlgorithm()) {
                return true;
            }
        }
        return false;
    }

    public Boolean isSignatureValid() {
        return signatureComputations.getSignatureValid();
    }
}
