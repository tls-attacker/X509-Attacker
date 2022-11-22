/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.x509.base.publickey.DhPublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.DsaPublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.EcdhEcdsaPublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.EcdhPublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.Ed25519PublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.Ed448PublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.PublicKeyBitString;
import de.rub.nds.x509attacker.x509.base.publickey.RsaPublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.X25519PublicKey;
import de.rub.nds.x509attacker.x509.base.publickey.X448PublicKey;

/**
 *
 * SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier,
 * subjectPublicKeyBitString BIT STRING }
 *
 */
public class SubjectPublicKeyInfo extends Asn1Sequence {

    @HoldsModifiableVariable
    private AlgorithmIdentifier algorithm;

    @HoldsModifiableVariable
    private PublicKeyBitString subjectPublicKeyBitString;

    public SubjectPublicKeyInfo(String identifier, X509CertificateConfig config) {
        super(identifier);
        algorithm = new AlgorithmIdentifier("algorithm");
        subjectPublicKeyBitString = new PublicKeyBitString("subjectPublicKeyBitstring", createSubjectPublicKeyStruct(config.getPublicKeyType()));
        initPublicKeyParameters(config);
        addChild(algorithm);
        addChild(subjectPublicKeyBitString);
    }

    public AlgorithmIdentifier getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(AlgorithmIdentifier algorithm) {
        this.algorithm = algorithm;
    }

    public PublicKeyBitString getSubjectPublicKeyBitString() {
        return subjectPublicKeyBitString;
    }

    public void setSubjectPublicKeyBitString(PublicKeyBitString subjectPublicKeyBitString) {
        this.subjectPublicKeyBitString = subjectPublicKeyBitString;
    }

    private X509Component createSubjectPublicKeyStruct(X509PublicKeyType publicKeyType) {
        switch (publicKeyType) {
            case DH:
                return new DhPublicKey();
            case DSA:
                return new DsaPublicKey();
            case ECDH_ECDSA:
                return new EcdhEcdsaPublicKey();
            case ECDH_ONLY:
                return new EcdhPublicKey();
            case ECMQV:
                throw new UnsupportedOperationException("ECMQV no supported");
            case ED25519:
                return new Ed25519PublicKey();
            case ED448:
                return new Ed448PublicKey();
            case GOST_R3411_2001:
                throw new UnsupportedOperationException("GOST_R3411_2001 no supported");
            case GOST_R3411_94:
                throw new UnsupportedOperationException("GOST_R3411_94 no supported");
            case KEA:
                throw new UnsupportedOperationException("KEA no supported");
            case RSA:
                return new RsaPublicKey();
            case RSAES_OAEP:
                throw new UnsupportedOperationException("RSAoaep no supported");
            case RSASSA_PSS:
                throw new UnsupportedOperationException("RSASSA_PSS no supported");
            case X25519:
                return new X25519PublicKey();
            case X448:
                return new X448PublicKey();
            default:
                throw new UnsupportedOperationException(
                        "PublicKeyType: " + publicKeyType.getHumanReadableName() + " is not supported.");
        }
    }

    private void initPublicKeyParameters(X509CertificateConfig config) {
        Asn1Field field = null;
        switch (config.getPublicKeyType()) {
            case DH:
                break;
            case RSA:
                break;
            case ECDH_ECDSA:
                break;
            case ECDH_ONLY:
                break;
            case ED25519:
                break;
            case ED448:
                break;
            case DSA:
                break;
            case X25519:
                break;
            case X448:
                break;
            case RSASSA_PSS:
                break;
            default:
                throw new UnsupportedOperationException(
                        "PublicKeyType: " + config.getPublicKeyType().getHumanReadableName() + " is not supported");
        }
        if (field != null) {
            algorithm.instantiateParameters(field);
        } else {
            algorithm.instantiateParameters(new Asn1Null("parameters"));
        }
    }

}
