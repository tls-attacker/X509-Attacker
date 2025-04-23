/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.util;

import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.protocol.crypto.key.DsaPublicKey;
import de.rub.nds.protocol.crypto.key.KeyGenerator;
import de.rub.nds.protocol.crypto.key.RsaPrivateKey;
import de.rub.nds.protocol.crypto.key.RsaPublicKey;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import de.rub.nds.x509attacker.x509.model.publickey.PublicKeyBitString;
import de.rub.nds.x509attacker.x509.preparator.X509CertificatePreparator;
import de.rub.nds.x509attacker.x509.preparator.X509ContainerPreparator;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.List;
import java.util.Random;
import org.apache.commons.lang3.tuple.Pair;

/**
 * A class to rewrite certificates. Takes in a base certificate chain and a config private keys and
 * changes the public key and signature in the provided certificate. It may be necessary that the
 * mimicry engine changes the keys provided to better mimic the original certificate. The new keys
 * will be writen to the config.
 */
public class MimicryEngine {

    public static X509CertificateChain createMimicryCertificateChain(
            List<X509CertificateConfig> privateKeyConfigs, X509CertificateChain originalChain) {
        if (privateKeyConfigs.size() != originalChain.size()) {
            throw new IllegalArgumentException(
                    "Number of private keys must match number of certificates in the chain");
        }

        // First we create a copy to modify
        X509CertificateChain mimicryCertificateChain = new X509CertificateChain();
        for (X509Certificate cert : originalChain.getCertificateList()) {
            X509Certificate copy = new X509Certificate("cert");
            X509Chooser chooser = new X509Chooser(new X509CertificateConfig(), new X509Context());

            copy.getParser(chooser)
                    .parse(
                            new BufferedInputStream(
                                    new ByteArrayInputStream(
                                            cert.getSerializer(chooser).serialize())));
            mimicryCertificateChain.addCertificate(copy);
        }

        // Then we modify the copy
        for (int i = mimicryCertificateChain.size() - 1; i >= 0; i--) {
            // The upper most certificate is selfsigned
            X509CertificateConfig signatureKeyConfig;
            boolean selfsigned = false;
            if (i == 0) {
                signatureKeyConfig = privateKeyConfigs.get(i);
                selfsigned = true;
            } else {
                signatureKeyConfig = privateKeyConfigs.get(i - 1);
            }

            X509CertificateConfig publicKeyConfig = privateKeyConfigs.get(i);
            X509Certificate currenCertificate = mimicryCertificateChain.getCertificateList().get(i);
            adjustPublicKey(publicKeyConfig, currenCertificate);
            adjustSignature(signatureKeyConfig, currenCertificate, selfsigned);
        }
        return mimicryCertificateChain;
    }

    private static void adjustSignature(
            X509CertificateConfig signatureKeyConfig,
            X509Certificate certificate,
            boolean selfsigned) {
        signatureKeyConfig.setSignatureAlgorithm(certificate.getX509SignatureAlgorithm());
        if (selfsigned) {

            signatureKeyConfig.setDefaultIssuerPublicKeyType(signatureKeyConfig.getPublicKeyType());
            signatureKeyConfig.setDefaultIssuerNamedCurve(
                    X509NamedCurve.getX509NamedCurve(certificate.getEllipticCurve()));

            if (certificate.getCertificateKeyType() == X509PublicKeyType.RSA) {
                signatureKeyConfig.setDefaultIssuerRsaModulus(
                        signatureKeyConfig.getDefaultSubjectRsaModulus());
                signatureKeyConfig.setDefaultIssuerRsaPrivateKey(
                        signatureKeyConfig.getDefaultSubjectRsaPrivateKey());
                signatureKeyConfig.setDefaultIssuerRsaPublicKey(
                        signatureKeyConfig.getDefaultSubjectRsaPublicExponent());
            }
        }

        X509Chooser chooser = new X509Chooser(signatureKeyConfig, new X509Context());
        X509CertificatePreparator certificatePreparator =
                (X509CertificatePreparator) certificate.getPreparator(chooser);
        certificatePreparator.prepareSignature();
        certificate.setContent(certificatePreparator.encodeChildrenContent());
        Asn1PreparatorHelper.prepareAfterContent(certificate);
    }

    private static void adjustPublicKey(
            X509CertificateConfig publicKeyConfig, X509Certificate certificate) {
        X509Chooser chooser = new X509Chooser(publicKeyConfig, new X509Context());
        publicKeyConfig.setPublicKeyType(certificate.getCertificateKeyType());
        publicKeyConfig.setDefaultSubjectNamedCurve(
                X509NamedCurve.getX509NamedCurve(certificate.getEllipticCurve()));
        if (certificate.getCertificateKeyType() == X509PublicKeyType.RSA) {
            int bitLength = certificate.getPublicKeyContainer().length();
            BigInteger publicExponent =
                    ((RsaPublicKey) certificate.getPublicKeyContainer()).getPublicExponent();
            Pair<RsaPublicKey, RsaPrivateKey> rsaKeys =
                    KeyGenerator.generateRsaKeys(publicExponent, bitLength, new Random(0));
            publicKeyConfig.setDefaultSubjectRsaModulus(rsaKeys.getLeft().getModulus());
            publicKeyConfig.setDefaultSubjectRsaPublicKey(rsaKeys.getLeft().getPublicExponent());
            publicKeyConfig.setDefaultSubjectRsaPrivateKey(rsaKeys.getRight().getPrivateExponent());
        }
        if (certificate.getCertificateKeyType() == X509PublicKeyType.DSA) {
            DsaPublicKey dsaPublicKey =
                    KeyGenerator.generateDsaPublicKey(
                            publicKeyConfig.getDefaultSubjectDsaPrivateKey(),
                            ((DsaPublicKey) certificate.getPublicKeyContainer()).getGenerator(),
                            ((DsaPublicKey) certificate.getPublicKeyContainer()).getModulus(),
                            ((DsaPublicKey) certificate.getPublicKeyContainer()).getQ());
            publicKeyConfig.setDefaultSubjectDsaGenerator(dsaPublicKey.getGenerator());
            publicKeyConfig.setDefaultSubjectDsaPrimeP(dsaPublicKey.getModulus());
            publicKeyConfig.setDefaultSubjectDsaPrimeQ(dsaPublicKey.getQ());
            publicKeyConfig.setDefaultSubjectDsaPublicKey(dsaPublicKey.getY());
        }
        PublicKeyBitString subjectPublicKeyBitString =
                certificate
                        .getTbsCertificate()
                        .getSubjectPublicKeyInfo()
                        .getSubjectPublicKeyBitString();
        subjectPublicKeyBitString.getPreparator(chooser).prepare();
        Asn1PreparatorHelper.prepareAfterContent(subjectPublicKeyBitString);
        certificate
                .getTbsCertificate()
                .getSubjectPublicKeyInfo()
                .getSerializer(chooser)
                .serialize();
        @SuppressWarnings("rawtypes")
        X509ContainerPreparator containerPreparator =
                (X509ContainerPreparator)
                        certificate
                                .getTbsCertificate()
                                .getSubjectPublicKeyInfo()
                                .getPreparator(chooser);
        certificate
                .getTbsCertificate()
                .getSubjectPublicKeyInfo()
                .setContent(containerPreparator.encodeChildrenContent());
        Asn1PreparatorHelper.prepareAfterContent(
                certificate.getTbsCertificate().getSubjectPublicKeyInfo());
        containerPreparator =
                (X509ContainerPreparator<?>) certificate.getTbsCertificate().getPreparator(chooser);
        certificate.getTbsCertificate().setContent(containerPreparator.encodeChildrenContent());
        Asn1PreparatorHelper.prepareAfterContent(certificate.getTbsCertificate());
        containerPreparator = (X509ContainerPreparator<?>) certificate.getPreparator(chooser);
        certificate.setContent(containerPreparator.encodeChildrenContent());
        Asn1PreparatorHelper.prepareAfterContent(certificate);
    }
}
