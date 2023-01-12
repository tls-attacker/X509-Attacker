/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import de.rub.nds.asn1.handler.EmptyHandler;
import de.rub.nds.asn1.handler.Handler;
import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.Asn1SequenceParser;
import de.rub.nds.modifiablevariable.HoldsModifiableVariable;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.base.publickey.PublicKeyBitString;
import de.rub.nds.x509attacker.x509.base.publickey.parameters.EcNamedCurveParameters;
import de.rub.nds.x509attacker.x509.parser.SubjectPublicKeyInfoParser;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;

/**
 * SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKeyBitString BIT
 * STRING }
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SubjectPublicKeyInfo extends Asn1Sequence<X509Chooser> {

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
        addChild(algorithm);
        addChild(subjectPublicKeyBitString);
    }

    public SubjectPublicKeyInfo(String identifier) {
        super(identifier);
        algorithm = new SubjectPublicKeyAlgorithmIdentifier("algorithm");
        subjectPublicKeyBitString = new PublicKeyBitString("subjectPublicKeyBitstring");
        addChild(algorithm);
        addChild(subjectPublicKeyBitString);
    }

    public SubjectPublicKeyAlgorithmIdentifier getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(SubjectPublicKeyAlgorithmIdentifier algorithm) {
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
                field = new EcNamedCurveParameters("namedCurveParameters");
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

    @Override
    public Handler getHandler(X509Chooser chooser) {
        return new EmptyHandler(chooser);
    }

    @Override
    public Asn1SequenceParser getParser(X509Chooser chooser) {
        return new SubjectPublicKeyInfoParser(chooser, this);
    }
}
