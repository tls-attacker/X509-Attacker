/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator.publickey;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.model.publickey.X509Ed25519PublicKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class Ed25519PublicKeyPreparatorTest {

    private X509Ed25519PublicKey publicKey;
    private X509Chooser chooser;
    private Ed25519PublicKeyPreparator preparator;
    private X509CertificateConfig config;
    private X509Context context;

    @BeforeEach
    public void setUp() {
        publicKey = new X509Ed25519PublicKey();
        config = new X509CertificateConfig();
        context = new X509Context(config);
        chooser = new X509Chooser(config, context);
        preparator = new Ed25519PublicKeyPreparator(chooser, publicKey);
    }

    @Test
    public void testPrepareWithDefaultKey() {
        preparator.prepare();

        assertNotNull(publicKey.getContent());
        assertNotNull(publicKey.getContent().getValue());
        // Ed25519 public keys are 32 bytes
        assertArrayEquals(
                config.getDefaultSubjectEd25519PublicKey(), publicKey.getContent().getValue());
    }

    @Test
    public void testPrepareWithCustomKey() {
        byte[] customKey =
                ArrayConverter.hexStringToByteArray(
                        "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");
        context.setSubjectEd25519PublicKey(customKey);

        preparator.prepare();

        assertNotNull(publicKey.getContent());
        assertNotNull(publicKey.getContent().getValue());
        assertArrayEquals(customKey, publicKey.getContent().getValue());
    }
}
