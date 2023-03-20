/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.handler.Handler;
import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.crypto.key.DhPublicKey;
import de.rub.nds.protocol.crypto.key.DsaPublicKey;
import de.rub.nds.protocol.crypto.key.EcdhPublicKey;
import de.rub.nds.protocol.crypto.key.EcdsaPublicKey;
import de.rub.nds.protocol.crypto.key.PublicKeyContainer;
import de.rub.nds.protocol.crypto.key.RsaPublicKey;
import de.rub.nds.protocol.crypto.signature.SignatureComputations;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.ExtendedKeyUsage;
import de.rub.nds.x509attacker.constants.KeyUsage;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.constants.X509Version;
import de.rub.nds.x509attacker.x509.base.publickey.PublicKeyBitString;
import de.rub.nds.x509attacker.x509.base.publickey.PublicKeyContent;
import de.rub.nds.x509attacker.x509.base.publickey.X509DhPublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.X509DsaPublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.X509EcdhEcdsaPublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.X509EcdhPublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.X509Ed25519PublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.X509Ed448PublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.X509RsaPublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.X509X25519PublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.X509X448PublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.PublicParameters;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509DhParameters;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.X509DssParameters;
import de.rub.nds.x509attacker.x509.preparator.X509CertificatePreparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.math.BigInteger;
import java.util.List;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Certificate extends Asn1Sequence<X509Chooser> {

    private static final Logger LOGGER = LogManager.getLogger();

    @HoldsModifiableVariable private TbsCertificate tbsCertificate;

    @HoldsModifiableVariable
    private CertificateSignatureAlgorithmIdentifier signatureAlgorithmIdentifier;

    @HoldsModifiableVariable private Asn1PrimitiveBitString<X509Chooser> signature;

    @HoldsModifiableVariable private SignatureComputations signatureComputations;

    public X509Certificate(String identifier, X509CertificateConfig certificateConfig) {
        super(identifier);
        tbsCertificate = new TbsCertificate("tbsCertificate", certificateConfig);
        signatureAlgorithmIdentifier =
                new CertificateSignatureAlgorithmIdentifier("signatureAlgorithm");
        signature = new Asn1PrimitiveBitString<X509Chooser>("signature");
        addChild(tbsCertificate);
        addChild(signatureAlgorithmIdentifier);
        addChild(signature);
    }

    public X509Certificate(String identifier) {
        super(identifier);
        tbsCertificate = new TbsCertificate("tbsCertificate");
        signatureAlgorithmIdentifier =
                new CertificateSignatureAlgorithmIdentifier("signatureAlgorithm");
        signature = new Asn1PrimitiveBitString<X509Chooser>("signature");
        addChild(tbsCertificate);
        addChild(signatureAlgorithmIdentifier);
        addChild(signature);
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

    public Asn1PrimitiveBitString<X509Chooser> getSignature() {
        return signature;
    }

    public void setSignature(Asn1PrimitiveBitString<X509Chooser> signature) {
        this.signature = signature;
    }

    @Override
    public X509CertificatePreparator getPreparator(X509Chooser chooser) {
        return new X509CertificatePreparator(chooser, this);
    }

    @Override
    public Asn1FieldSerializer getSerializer() {
        return new Asn1FieldSerializer(this);
    }

    @Override
    public Handler<X509Chooser> getHandler(X509Chooser chooser) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public byte[] getSha256Fingerprint() {
        return null;
    }

    public boolean isEllipticCurveCertificate() {

        PublicKeyContent publicKey = getPublicKey();
        if (publicKey != null) {
            return publicKey.isEllipticCurve();
        } else {
            // Certificate does not seem to have a public key
            return false;
        }
    }

    public X509PublicKeyType getCertificateKeyType() {
        PublicKeyContent publicKey = getPublicKey();
        if (publicKey == null) {
            return null;
        }
        if (publicKey instanceof X509DhPublicKey) {
            return X509PublicKeyType.DH;
        }
        if (publicKey instanceof X509RsaPublicKey) {
            return X509PublicKeyType.RSA;
        }
        if (publicKey instanceof X509DsaPublicKey) {
            return X509PublicKeyType.DSA;
        }
        if (publicKey instanceof X509EcdhEcdsaPublicKey) {
            return X509PublicKeyType.ECDH_ECDSA;
        }
        if (publicKey instanceof X509EcdhPublicKey) {
            return X509PublicKeyType.ECDH_ONLY;
        }
        if (publicKey instanceof X509Ed25519PublicKey) {
            return X509PublicKeyType.ED25519;
        }
        if (publicKey instanceof X509Ed448PublicKey) {
            return X509PublicKeyType.ED448;
        }
        if (publicKey instanceof X509X25519PublicKey) {
            return X509PublicKeyType.X25519;
        }
        if (publicKey instanceof X509X448PublicKey) {
            return X509PublicKeyType.X448;
        }
        LOGGER.warn(
                "The public key "
                        + publicKey.toString()
                        + " has not been correctly integrated into TLS-Attacker. Returning NONE");
        return null;
    }

    public NamedEllipticCurveParameters getEllipticCurve() {
        if (isEllipticCurveCertificate()) {
            PublicKeyContent publicKey = getPublicKey();
            if (publicKey instanceof X509X25519PublicKey) {
                return NamedEllipticCurveParameters.CURVE_X25519;
            } else if (publicKey instanceof X509X448PublicKey) {
                return NamedEllipticCurveParameters.CURVE_X448;
            } else {
                throw new UnsupportedOperationException("not implemented yet");
            }
        } else {
            return null;
        }
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
        throw new UnsupportedOperationException("not implemented yet");
    }

    public X509NamedCurve getSignatureNamedGroup() {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from
        // nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    public PublicKeyContainer getPublicKeyContainer() {
        X509PublicKeyType certificateKeyType = getCertificateKeyType();
        switch (certificateKeyType) {
            case DH:
                BigInteger publicKey =
                        ((X509DhPublicKey) getPublicKey()).getPublicKey().getValue().getValue();
                BigInteger generator =
                        ((X509DhParameters) getPublicParameters()).getG().getValue().getValue();
                BigInteger modulus =
                        ((X509DhParameters) getPublicParameters()).getP().getValue().getValue();
                return new DhPublicKey(publicKey, generator, modulus);
            case DSA:
                BigInteger Q =
                        ((X509DssParameters) getPublicParameters()).getQ().getValue().getValue();
                BigInteger X =
                        ((X509DsaPublicKey) getPublicKey()).getPublicKeyY().getValue().getValue();
                generator =
                        ((X509DssParameters) getPublicParameters()).getG().getValue().getValue();
                modulus = ((X509DssParameters) getPublicParameters()).getP().getValue().getValue();
                return new DsaPublicKey(Q, X, generator, modulus);
            case ECDH_ECDSA:
                BigInteger xCoordinate =
                        ((X509EcdhEcdsaPublicKey) getPublicKey()).getxCoordinate().getValue();
                BigInteger yCoordinate =
                        ((X509EcdhEcdsaPublicKey) getPublicKey()).getyCoordinate().getValue();
                NamedEllipticCurveParameters parameters =
                        (NamedEllipticCurveParameters) getEllipticCurve();
                return new EcdsaPublicKey(
                        parameters.getCurve().getPoint(xCoordinate, yCoordinate), parameters);
            case ECDH_ONLY:
                xCoordinate = ((X509EcdhPublicKey) getPublicKey()).getxCoordinate().getValue();
                yCoordinate = ((X509EcdhPublicKey) getPublicKey()).getyCoordinate().getValue();
                parameters = (NamedEllipticCurveParameters) getEllipticCurve();
                return new EcdhPublicKey(
                        parameters.getCurve().getPoint(xCoordinate, yCoordinate), parameters);
            case RSA:
                modulus =
                        ((X509RsaPublicKey) getPublicKey())
                                .getRsaPublicKeyContentSequence()
                                .getModulus()
                                .getValue()
                                .getValue();
                BigInteger publicExponent =
                        ((X509RsaPublicKey) getPublicKey())
                                .getRsaPublicKeyContentSequence()
                                .getPublicExponent()
                                .getValue()
                                .getValue();
                return new RsaPublicKey(publicExponent, modulus);
            default:
                throw new UnsupportedOperationException(
                        "PublicKeyContainer " + certificateKeyType + " not yet implemented");
        }
    }

    public DateTime getNotBefore() {
        return tbsCertificate.getValidity().getNotBefore().getTimeValue();
    }

    public DateTime getNotAfter() {
        return tbsCertificate.getValidity().getNotAfter().getTimeValue();
    }

    public Boolean isExpired() {
        return getNotAfter().isAfterNow();
    }

    public Boolean isYetValid() {
        return getNotBefore().isAfterNow();
    }

    public Boolean isRevokedCrl() {
        return null; // TODO Implement
    }

    public Boolean isRevokedOcsp() {
        return null; // TODO Implement
    }

    public HashAlgorithm getHashAlgorithm() {
        return null; // TODO implement
    }

    public Boolean hasWeakBlacklistedDebianKey() {
        return null; // TODO Implement
    }

    public Boolean isLeaf() {
        return null; // TODO Implement
    }

    public Boolean isValidLeafFor(String uri) {
        return null; // TODO Implement
    }

    public String getCommonName() {
        return null; // TODO Implement
    }

    public List<String> getSubjectAlternativeNames() {
        return null; // TODO Implement
    }

    public Boolean hasSanExtension() {
        return null; // TODO Implement
    }

    public Boolean hasExtendedKeyUsageExtension() {
        return null; // TODO Implement
    }

    public Boolean hasSignedCertificateTransparencyEntry() {
        return null; // TODO Implement
    }

    public Boolean hasOcsp() {
        return null; // TODO Implement
    }

    public Boolean hasCertificateRevocationList() {
        return null; // TODO Implement
    }

    public Boolean isOcspMustStaple() {
        return null; // TODO Implement
    }

    public Boolean isSelfSigned() {
        return null; // TODO Implement
    }

    private String getRdnString(List<RelativeDistinguishedName> relativeDistinguishedNames) {
        StringBuilder builder = new StringBuilder();
        for (RelativeDistinguishedName relativeDistinguishedName : relativeDistinguishedNames) {
            for (Asn1Encodable<X509Chooser> encodable : relativeDistinguishedName.getChildren()) {
                if (encodable instanceof AttributeTypeAndValue) {
                    builder.append(((AttributeTypeAndValue) encodable).getStringRepresentation());
                    builder.append(" ");
                }
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
        return tbsCertificate.getVersion().getVersion();
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        ObjectIdentifier oid =
                new ObjectIdentifier(
                        getSignatureAlgorithmIdentifier().getAlgorithm().getValue().getValue());
        return X509SignatureAlgorithm.decodeFromOidBytes(oid.getEncoded()).getSignatureAlgorithm();
    }

    public List<KeyUsage> getKeyUsages() {
        return null; // TODO implement
    }

    public List<ExtendedKeyUsage> getExtendedKeyUsages() {
        return null; // TODO implement
    }

    public SignatureComputations getSignatureComputations() {
        return signatureComputations;
    }

    public void setSignatureComputations(SignatureComputations signatureComputations) {
        this.signatureComputations = signatureComputations;
    }
}
