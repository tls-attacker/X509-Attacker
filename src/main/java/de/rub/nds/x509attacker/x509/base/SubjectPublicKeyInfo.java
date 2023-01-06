/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.base.publickey.PublicKeyBitString;

/**
 * SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKeyBitString BIT
 * STRING }
 */
public class SubjectPublicKeyInfo extends Asn1Sequence<X509Chooser> {

    @HoldsModifiableVariable private AlgorithmIdentifier algorithm;

    @HoldsModifiableVariable private PublicKeyBitString subjectPublicKeyBitString;

    public SubjectPublicKeyInfo(String identifier, X509CertificateConfig config) {
        super(identifier);
        algorithm = new AlgorithmIdentifier("algorithm");
        subjectPublicKeyBitString = new PublicKeyBitString("subjectPublicKeyBitstring");
        initPublicKeyParameters(config);
        addChild(algorithm);
        addChild(subjectPublicKeyBitString);
    }

    public SubjectPublicKeyInfo(String identifier) {
        super(identifier);
        algorithm = new AlgorithmIdentifier("algorithm");
        subjectPublicKeyBitString = new PublicKeyBitString("subjectPublicKeyBitstring");
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
                        "PublicKeyType: "
                                + config.getPublicKeyType().getHumanReadableName()
                                + " is not supported");
        }
        if (field != null) {
            algorithm.instantiateParameters(field);
        } else {
            algorithm.instantiateParameters(new Asn1Null("parameters"));
        }
    }
}
