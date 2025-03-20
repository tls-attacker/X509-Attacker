/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.util;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

import de.rub.nds.asn1.preparator.Asn1PreparatorHelper;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.filesystem.CertificateIo;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import de.rub.nds.x509attacker.x509.preparator.X509CertificatePreparator;

/**
 * Tests that verify modifications to certificate structures are reflected in the serialized output.
 */
class ModificationVerificationTest {

    /**
     * Test that verifies modifications to a certificate's signature are correctly reflected in the
     * serialized output.
     *
     * @throws IOException
     */
    @Test
    void testSignatureModification() throws IOException {

        // Create a certificate chain from a test certificate
        X509CertificateChain exampleServerCertificateChain =
                CertificateIo.readPemChain(
                        getClass().getResourceAsStream("/testcerts/rsa2048_cert.pem"));
        assertNotNull(exampleServerCertificateChain, "Failed to load test certificate");

        // Create configurations for the mimicry certificate chain
        List<X509CertificateConfig> certificateConfigs = List.of(new X509CertificateConfig());

        // Create a mimicry certificate chain
        X509CertificateChain mimicryCertificateChain =
                MimicryEngine.createMimicryCertificateChain(
                        certificateConfigs, exampleServerCertificateChain);

        // Get the original serialized form
        X509Chooser chooser = new X509Chooser(new X509CertificateConfig(), new X509Context());
        byte[] originalSerialized =
                mimicryCertificateChain.getCertificate(0).getSerializer(chooser).serialize();

        // Modify the signature content to empty array - using setOriginalValue

        mimicryCertificateChain.getCertificate(0).getSignature().getContent().addModification(new ByteArrayExplicitValueModification(new byte[0]));
        mimicryCertificateChain.getCertificate(0).getSignature().getTagOctets().addModification(new ByteArrayExplicitValueModification(new byte[0]));
        mimicryCertificateChain.getCertificate(0).getSignature().getLengthOctets().addModification(new ByteArrayExplicitValueModification(new byte[0]));
        Asn1PreparatorHelper.prepareAfterContent(
                mimicryCertificateChain.getCertificate(0).getSignature());
        X509CertificatePreparator preparator =
                (X509CertificatePreparator)
                        mimicryCertificateChain.getCertificate(0).getPreparator(null);
        mimicryCertificateChain.getCertificate(0).setContent(preparator.encodeChildrenContent());
        Asn1PreparatorHelper.prepareAfterContent(mimicryCertificateChain.getCertificate(0));

        // Get the modified serialized form
        byte[] modifiedSerialized =
                mimicryCertificateChain.getCertificate(0).getSerializer(chooser).serialize();

        // Verify the serialized output is different
        assertFalse(
                Arrays.equals(originalSerialized, modifiedSerialized),
                "Serialized output should be different after signature modification");
        // Print the original and modified serialized forms
        System.out.println(
                "Original Serialized: " + ArrayConverter.bytesToHexString(originalSerialized));
        System.out.println(
                "Modified Serialized: " + ArrayConverter.bytesToHexString(modifiedSerialized));
    }
}
