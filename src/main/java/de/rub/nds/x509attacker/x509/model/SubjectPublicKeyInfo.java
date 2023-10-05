/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.protocol.crypto.key.DhPublicKey;
import de.rub.nds.protocol.crypto.key.DsaPublicKey;
import de.rub.nds.protocol.crypto.key.EcdhPublicKey;
import de.rub.nds.protocol.crypto.key.EcdsaPublicKey;
import de.rub.nds.protocol.crypto.key.PublicKeyContainer;
import de.rub.nds.protocol.crypto.key.RsaPublicKey;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.x509.handler.SubjectPublicKeyInfoHandler;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.model.publickey.PublicKeyBitString;
import de.rub.nds.x509attacker.x509.model.publickey.PublicKeyContent;
import de.rub.nds.x509attacker.x509.model.publickey.X509DhPublicKey;
import de.rub.nds.x509attacker.x509.model.publickey.X509DsaPublicKey;
import de.rub.nds.x509attacker.x509.model.publickey.X509EcdhEcdsaPublicKey;
import de.rub.nds.x509attacker.x509.model.publickey.X509EcdhPublicKey;
import de.rub.nds.x509attacker.x509.model.publickey.X509RsaPublicKey;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.PublicParameters;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509DhParameters;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509DssParameters;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509EcNamedCurveParameters;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509NullParameters;
import de.rub.nds.x509attacker.x509.parser.SubjectPublicKeyInfoParser;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.SubjectPublicKeyInfoPreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.math.BigInteger;

/**
 * SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKeyBitString BIT
 * STRING }
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SubjectPublicKeyInfo extends Asn1Sequence implements X509Component {

    @HoldsModifiableVariable private SubjectPublicKeyAlgorithmIdentifier algorithm;

    @HoldsModifiableVariable private PublicKeyBitString subjectPublicKeyBitString;

    private SubjectPublicKeyInfo() {
        super(null);
    }

    public SubjectPublicKeyInfo(String identifier, X509CertificateConfig config) {
        super(identifier);
        algorithm = new SubjectPublicKeyAlgorithmIdentifier("algorithm");
        subjectPublicKeyBitString = new PublicKeyBitString("subjectPublicKeyBitstring", config);
        initPublicKeyParameters(config);
    }

    public SubjectPublicKeyInfo(String identifier) {
        super(identifier);
        algorithm = new SubjectPublicKeyAlgorithmIdentifier("algorithm");
        subjectPublicKeyBitString = new PublicKeyBitString("subjectPublicKeyBitstring");
    }

    public void setAlgorithm(SubjectPublicKeyAlgorithmIdentifier algorithm) {
        this.algorithm = algorithm;
    }

    public SubjectPublicKeyAlgorithmIdentifier getAlgorithm() {
        return algorithm;
    }

    public PublicKeyBitString getSubjectPublicKeyBitString() {
        return subjectPublicKeyBitString;
    }

    public void setSubjectPublicKeyBitString(PublicKeyBitString subjectPublicKeyBitString) {
        this.subjectPublicKeyBitString = subjectPublicKeyBitString;
    }

    private void initPublicKeyParameters(X509CertificateConfig config) {
        PublicParameters publicParameters = null;
        switch (config.getPublicKeyType()) {
            case DH:
                publicParameters = new X509DhParameters("dhParameters");
                break;
            case ECDH_ECDSA:
                publicParameters = new X509EcNamedCurveParameters("namedCurveParameters");
                break;
            case RSA:
                publicParameters = new X509NullParameters("nullParameters");
                break;
            case ECDH_ONLY:
            case ED25519:
            case ED448:
            case DSA:
            case X25519:
            case X448:
            case RSASSA_PSS:
                publicParameters = new X509NullParameters("nullParameters");
                break;
            default:
                throw new UnsupportedOperationException(
                        "PublicKeyType: "
                                + config.getPublicKeyType().getHumanReadableName()
                                + " is not supported");
        }
        algorithm.setParameters(publicParameters);
    }

    @Override
    public X509Handler getHandler(X509Chooser chooser) {
        return new SubjectPublicKeyInfoHandler(chooser, this);
    }

    @Override
    public X509Parser getParser(X509Chooser chooser) {
        return new SubjectPublicKeyInfoParser(chooser, this);
    }

    @Override
    public X509Preparator getPreparator(X509Chooser chooser) {
        return new SubjectPublicKeyInfoPreparator(chooser, this);
    }

    public PublicKeyContainer getPublicKeyContainer() {
        X509PublicKeyType certificateKeyType =
                subjectPublicKeyBitString.getX509PublicKeyContent().getX509PublicKeyType();
        PublicKeyContent content = subjectPublicKeyBitString.getX509PublicKeyContent();
        switch (certificateKeyType) {
            case DH:
                BigInteger publicKey = ((X509DhPublicKey) content).getValue().getValue();
                BigInteger generator =
                        ((X509DhParameters) algorithm.getParameters()).getG().getValue().getValue();
                BigInteger modulus =
                        ((X509DhParameters) algorithm.getParameters()).getP().getValue().getValue();
                return new DhPublicKey(publicKey, generator, modulus);
            case DSA:
                BigInteger Q =
                        ((X509DssParameters) algorithm.getParameters())
                                .getQ()
                                .getValue()
                                .getValue();
                BigInteger X = ((X509DsaPublicKey) content).getValue().getValue();
                generator =
                        ((X509DssParameters) algorithm.getParameters())
                                .getG()
                                .getValue()
                                .getValue();
                modulus =
                        ((X509DssParameters) algorithm.getParameters())
                                .getP()
                                .getValue()
                                .getValue();
                return new DsaPublicKey(Q, X, generator, modulus);
            case ECDH_ECDSA:
                BigInteger xCoordinate =
                        ((X509EcdhEcdsaPublicKey) content).getxCoordinate().getValue();
                BigInteger yCoordinate =
                        ((X509EcdhEcdsaPublicKey) content).getyCoordinate().getValue();
                NamedEllipticCurveParameters parameters =
                        X509NamedCurve.decodeFromOidBytes(
                                        ((X509EcNamedCurveParameters) algorithm.getParameters())
                                                .getValueAsOid()
                                                .getEncoded())
                                .getParameters();
                return new EcdsaPublicKey(
                        parameters.getGroup().getPoint(xCoordinate, yCoordinate), parameters);
            case ECDH_ONLY:
                xCoordinate = ((X509EcdhPublicKey) content).getxCoordinate().getValue();
                yCoordinate = ((X509EcdhPublicKey) content).getyCoordinate().getValue();
                parameters =
                        X509NamedCurve.decodeFromOidBytes(
                                        ((X509EcNamedCurveParameters) algorithm.getParameters())
                                                .getValueAsOid()
                                                .getEncoded())
                                .getParameters();
                return new EcdhPublicKey(
                        parameters.getGroup().getPoint(xCoordinate, yCoordinate), parameters);
            case RSA:
                modulus = ((X509RsaPublicKey) content).getModulus().getValue().getValue();
                BigInteger publicExponent =
                        ((X509RsaPublicKey) content).getPublicExponent().getValue().getValue();
                return new RsaPublicKey(publicExponent, modulus);
            default:
                throw new UnsupportedOperationException(
                        "PublicKeyContainer " + certificateKeyType + " not yet implemented");
        }
    }
}
