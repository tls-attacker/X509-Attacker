package de.rub.nds.x509attacker.util;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.List;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.filesystem.CertificateIo;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import de.rub.nds.x509attacker.x509.model.publickey.PublicKeyBitString;
import de.rub.nds.x509attacker.x509.preparator.X509CertificatePreparator;
import de.rub.nds.x509attacker.x509.preparator.X509ContainerPreparator;

/**
 * A class to rewrite certificates. Takes in a base certificate chain and a config private keys and changes the public key and signature in the provided certificate 
 */
public class MimicryEngine {

    public static X509CertificateChain createMimicryCertificate(List<X509CertificateConfig> privateKeyConfigs,
            X509CertificateChain originalChain) {
        if (privateKeyConfigs.size() != originalChain.size()) {
            throw new IllegalArgumentException("Number of private keys must match number of certificates in the chain");
        }

        // First we create a copy to modify
        X509CertificateChain mimicryCertificateChain = new X509CertificateChain();
        for (X509Certificate cert : originalChain.getCertificateList()) {
            X509Certificate copy;
            X509Chooser chooser = new X509Chooser(new X509CertificateConfig(), new X509Context());
            copy = new X509Certificate("cert");
            copy.getParser(chooser).parse(
                    new BufferedInputStream(new ByteArrayInputStream(cert.getSerializer(chooser).serialize())));

            mimicryCertificateChain.addCertificate(copy);
        }

        for (int i = mimicryCertificateChain.size() - 1; i > 0; i--) {
            // The upper most certificate is selfsigned
            X509CertificateConfig signatureKeyConfig;
            if (i == originalChain.size() - 1) {
                signatureKeyConfig = privateKeyConfigs.get(i);
            } else {
                signatureKeyConfig = privateKeyConfigs.get(i - 1);
            }
            X509CertificateConfig publicKeyConfig = privateKeyConfigs.get(i);
            X509Certificate currenCertificate = mimicryCertificateChain.getCertificateList().get(i);
            adjustPublicKey(publicKeyConfig, currenCertificate);
            adjustSignature(signatureKeyConfig, currenCertificate);

        }
        return mimicryCertificateChain;
    }

    private static void adjustSignature(X509CertificateConfig signatureKeyConfig, X509Certificate certificate) {
        X509Chooser chooser = new X509Chooser(signatureKeyConfig, new X509Context());
        X509CertificatePreparator certificatePreparator = (X509CertificatePreparator) certificate
                .getPreparator(chooser);
        certificatePreparator.prepareSignature();
        certificate.setContent(certificatePreparator.encodeChildrenContent());
    }

    private static void adjustPublicKey(X509CertificateConfig publicKeyConfig, X509Certificate certificate) {
        X509Chooser chooser = new X509Chooser(publicKeyConfig, new X509Context());
        PublicKeyBitString subjectPublicKeyBitString = certificate.getTbsCertificate()
                .getSubjectPublicKeyInfo().getSubjectPublicKeyBitString();
        subjectPublicKeyBitString.getPreparator(chooser).prepare();

        certificate.getTbsCertificate().getSubjectPublicKeyInfo().getSerializer(chooser).serialize();
        @SuppressWarnings("rawtypes")
        X509ContainerPreparator containerPreparator = (X509ContainerPreparator) certificate.getTbsCertificate()
                .getSubjectPublicKeyInfo().getPreparator(chooser);
        certificate.getTbsCertificate().getSubjectPublicKeyInfo()
                .setContent(containerPreparator.encodeChildrenContent());
        containerPreparator = (X509ContainerPreparator<?>) certificate.getTbsCertificate().getPreparator(chooser);
        certificate.getTbsCertificate().setContent(containerPreparator.encodeChildrenContent());
        containerPreparator = (X509ContainerPreparator<?>) certificate.getPreparator(chooser);
        certificate.setContent(containerPreparator.encodeChildrenContent());
    }
}
