/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.asn1.preparator.Asn1SequencePreparator;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.signatureengine.SignatureEngine;
import de.rub.nds.x509attacker.signatureengine.SignatureEngineFactory;
import de.rub.nds.x509attacker.signatureengine.keyparsers.SignatureKeyType;
import de.rub.nds.x509attacker.signatureengine.privatekey.CustomRsaPrivateKey;
import de.rub.nds.x509attacker.x509.base.X509Certificate;
import java.security.PrivateKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X509CertificatePreparator extends Asn1SequencePreparator<X509Chooser> {

    private final X509Certificate certificate;

    private static final Logger LOGGER = LogManager.getLogger();

    public X509CertificatePreparator(X509Chooser chooser, X509Certificate certificate) {
        super(chooser, certificate);
        this.certificate = certificate;
    }

    @Override
    protected byte[] encodeContent() {
        this.certificate.getTbsCertificate().getPreparator(chooser).prepare();
        prepareSignatureAlgorithm();
        prepareSignature();
        certificate.setEncodedChildren(encodedChildren(certificate.getChildren()));
        return certificate.getEncodedChildren().getValue();
    }

    private void prepareSignatureAlgorithm() {
        X509SignatureAlgorithm signatureAlgorithm = chooser.getSignatureAlgorithm();
        certificate
                .getSignatureAlgorithmIdentifier()
                .getAlgorithm()
                .setValue(signatureAlgorithm.getOid().toString());
        certificate
                .getSignatureAlgorithmIdentifier()
                .getAlgorithm()
                .getPreparator(chooser)
                .prepare();
        certificate
                .getSignatureAlgorithmIdentifier()
                .instantiateParameters(new Asn1Null<>("null")); // PARAMETERS
        certificate.getSignatureAlgorithmIdentifier().getPreparator(chooser).prepare();
    }

    private void prepareSignature() {
        X509SignatureAlgorithm signatureAlgorithm = chooser.getSignatureAlgorithm();
        SignatureEngine signatureEngine = SignatureEngineFactory.getEngine(signatureAlgorithm);
        PrivateKey privateKey = getPrivateKeyForAlgorithm(signatureAlgorithm);
        byte[] toBeSigned = this.certificate.getTbsCertificate().getSerializer().serialize();
        LOGGER.debug("To be signed: {}", toBeSigned);
        byte[] signature = signatureEngine.sign(privateKey, toBeSigned);
        LOGGER.debug("Signature: {}", signature);
        certificate.getSignature().setUsedBits(signature);
        certificate.getSignature().getPreparator(chooser).prepare();
    }

    private PrivateKey getPrivateKeyForAlgorithm(X509SignatureAlgorithm signatureAlgorithm) {
        SignatureKeyType keyType = signatureAlgorithm.getKeyType();
        switch (keyType) {
            case ECDSA:
                throw new UnsupportedOperationException(
                        "The keytype \"" + keyType.name() + "\" is not implemented yet");
            case RSA:
                return new CustomRsaPrivateKey(
                        chooser.getIssuerRsaModulus(), chooser.getIssuerRsaPrivateKey());
            case DSA:
                throw new UnsupportedOperationException(
                        "The keytype \"" + keyType.name() + "\" is not implemented yet");
            default:
                throw new UnsupportedOperationException(
                        "The keytype \"" + keyType.name() + "\" is not implemented yet");
        }
    }
}
