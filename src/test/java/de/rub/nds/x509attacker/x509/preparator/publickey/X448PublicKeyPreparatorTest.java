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
import de.rub.nds.x509attacker.x509.model.publickey.X509X448PublicKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class X448PublicKeyPreparatorTest {

    private X509X448PublicKey publicKey;
    private X509Chooser chooser;
    private X448PublicKeyPreparator preparator;
    private X509CertificateConfig config;
    private X509Context context;

    @BeforeEach
    public void setUp() {
        publicKey = new X509X448PublicKey();
        config = new X509CertificateConfig();
        context = new X509Context(config);
        chooser = new X509Chooser(config, context);
        preparator = new X448PublicKeyPreparator(chooser, publicKey);
    }

    @Test
    public void testPrepareWithDefaultKey() {
        preparator.prepare();

        assertNotNull(publicKey.getContent());
        assertNotNull(publicKey.getContent().getValue());
        // X448 public keys are 56 bytes
        assertArrayEquals(
                config.getDefaultSubjectX448PublicKey(), publicKey.getContent().getValue());
    }

    @Test
    public void testPrepareWithCustomKey() {
        byte[] customKey =
                ArrayConverter.hexStringToByteArray(
                        "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0");
        context.setSubjectX448PublicKey(customKey);

        preparator.prepare();

        assertNotNull(publicKey.getContent());
        assertNotNull(publicKey.getContent().getValue());
        assertArrayEquals(customKey, publicKey.getContent().getValue());
    }
}
