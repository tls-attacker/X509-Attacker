/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.signatureengine.SignatureEngine;
import de.rub.nds.x509attacker.signatureengine.SignatureEngineFactory;
import de.rub.nds.x509attacker.signatureengine.keyparsers.SignatureKeyType;
import de.rub.nds.x509attacker.signatureengine.privatekey.CustomRsaPrivateKey;
import de.rub.nds.x509attacker.x509.base.X509Certificate;
import java.security.PrivateKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X509CertificatePreparator extends X509ComponentPreparator {

    private final X509Certificate certificate;

    private static final Logger LOGGER = LogManager.getLogger();

    public X509CertificatePreparator(X509Certificate certificate, X509CertificateConfig config) {
        super(certificate, config);
        this.certificate = certificate;
    }

    @Override
    protected byte[] encodeContent() {
        prepareSubcomponent(this.certificate.getTbsCertificate(), config);
        prepareSignatureAlgorithm();
        prepareSignature();
        certificate.setEncodedChildren(encodedChildren(certificate.getChildren()));
        return certificate.getEncodedChildren().getValue();
    }

    private void prepareSignatureAlgorithm() {
        X509SignatureAlgorithm signatureAlgorithm = config.getSignatureAlgorithm();
        certificate.getSignatureAlgorithm().getAlgorithm().setValue(signatureAlgorithm.getOid().toString());
        prepareSubcomponent(certificate.getSignatureAlgorithm().getAlgorithm());
        certificate.getSignatureAlgorithm().instantiateParameters(new Asn1Null("null")); // PARAMETERS
        prepareSubcomponent(certificate.getSignatureAlgorithm());
    }

    private void prepareSignature() {
        byte[] encodedSignatureAlgorithm = certificate.getSignatureAlgorithm().getContent().getValue();
        X509SignatureAlgorithm signatureAlgorithm =
            X509SignatureAlgorithm.decodeFromOidBytes(encodedSignatureAlgorithm);
        if (signatureAlgorithm == null) {
            LOGGER.warn("Could not decode signature algorithm, using defaultSignatureAlgorithm");
            signatureAlgorithm = config.getSignatureAlgorithm();
        }
        SignatureEngine signatureEngine = SignatureEngineFactory.getEngine(signatureAlgorithm);
        PrivateKey privateKey = getPrivateKeyForAlgorithm(signatureAlgorithm);
        byte[] toBeSigned = this.certificate.getTbsCertificate().getGenericSerializer().serialize();
        byte[] signature = signatureEngine.sign(privateKey, toBeSigned);
        certificate.getSignature().setValue(signature);
        certificate.getSignature().setUnusedBits((byte) 0);
        prepareSubcomponent(certificate.getSignature());

    }

    private PrivateKey getPrivateKeyForAlgorithm(X509SignatureAlgorithm signatureAlgorithm) {
        SignatureKeyType keyType = signatureAlgorithm.getKeyType();
        switch (keyType) {

            case ECDSA:
                throw new UnsupportedOperationException(
                    "The keytype \"" + keyType.name() + "\" is not implemented yet");
            case RSA:
                return new CustomRsaPrivateKey(config.getRsaModulus(), config.getRsaPrivateKey());
            case DSA:
                throw new UnsupportedOperationException(
                    "The keytype \"" + keyType.name() + "\" is not implemented yet");
            default:
                throw new UnsupportedOperationException(
                    "The keytype \"" + keyType.name() + "\" is not implemented yet");
        }
    }
}
