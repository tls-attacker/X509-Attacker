/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.crypto.key.DsaPrivateKey;
import de.rub.nds.protocol.crypto.key.EcdsaPrivateKey;
import de.rub.nds.protocol.crypto.key.PrivateKeyContainer;
import de.rub.nds.protocol.crypto.key.RsaPrivateKey;
import de.rub.nds.protocol.crypto.signature.SignatureCalculator;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X509CertificatePreparator extends X509ContainerPreparator<X509Certificate> {

    private static final Logger LOGGER = LogManager.getLogger();

    public X509CertificatePreparator(X509Chooser chooser, X509Certificate certificate) {
        super(chooser, certificate);
    }

    private void prepareTbsCertificate() {
        field.getTbsCertificate().getPreparator(chooser).prepare();
        field.getTbsCertificate().getHandler(chooser).adjustContextAfterPrepare();
    }

    private void prepareSignatureAlgorithmIdentifier() {
        field.getSignatureAlgorithmIdentifier().getPreparator(chooser).prepare();
        field.getSignatureAlgorithmIdentifier().getHandler(chooser).adjustContextAfterPrepare();
    }

    public void prepareSignature() {
        SignatureCalculator signatureCalculator = new SignatureCalculator();

        X509SignatureAlgorithm signatureAlgorithm = chooser.getSignatureAlgorithm();
        if (field.getSignatureComputations() == null) {
            field.setSignatureComputations(
                    signatureCalculator.createSignatureComputations(
                            signatureAlgorithm.getSignatureAlgorithm()));
        }

        byte[] toBeSigned = this.field.getTbsCertificate().getSerializer(chooser).serialize();
        LOGGER.debug("To be signed: {}", toBeSigned);
        signatureCalculator.computeSignature(
                field.getSignatureComputations(),
                getPrivateKeyForAlgorithm(signatureAlgorithm.getSignatureAlgorithm()),
                toBeSigned,
                signatureAlgorithm.getSignatureAlgorithm(),
                chooser.getSignatureAlgorithm().getHashAlgorithm());

        LOGGER.debug(
                "Signature: {}", field.getSignatureComputations().getSignatureBytes().getValue());
        Asn1PreparatorHelper.prepareField(
                field.getSignature(),
                field.getSignatureComputations().getSignatureBytes().getValue(),
                (byte) 0);
    }

    private PrivateKeyContainer getPrivateKeyForAlgorithm(SignatureAlgorithm signatureAlgorithm) {
        switch (signatureAlgorithm) {
            case ECDSA:
                return new EcdsaPrivateKey(
                        chooser.getIssuerEcPrivateKey(),
                        chooser.getConfig().getDefaultIssuerNonce(),
                        chooser.getIssuerNamedCurve().getParameters());
            case RSA_PKCS1:
            case RSA_SSA_PSS:
                return new RsaPrivateKey(
                        chooser.getIssuerRsaModulus(), chooser.getIssuerRsaPrivateKey());
            case DSA:
                return new DsaPrivateKey(
                        chooser.getDsaPrimeQ(),
                        chooser.getIssuerDsaPrivateKey(),
                        chooser.getConfig().getDefaultIssuerDsaNonce(),
                        chooser.getDsaGenerator(),
                        chooser.getDsaPrimeP());
            default:
                throw new UnsupportedOperationException(
                        "The keytype \"" + signatureAlgorithm.name() + "\" is not implemented yet");
        }
    }

    @Override
    public void prepareSubComponents() {
        prepareTbsCertificate();
        prepareSignatureAlgorithmIdentifier();
        prepareSignature();
    }

    @Override
    public byte[] encodeChildrenContent() {
        List<Asn1Encodable> children = new ArrayList<>();
        children.add(field.getTbsCertificate());
        children.add(field.getSignatureAlgorithmIdentifier());
        children.add(field.getSignature());
        return encodeChildren(children);
    }
}
