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
import de.rub.nds.x509attacker.x509.model.publickey.X509Ed448PublicKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class Ed448PublicKeyPreparatorTest {

    private X509Ed448PublicKey publicKey;
    private X509Chooser chooser;
    private Ed448PublicKeyPreparator preparator;
    private X509CertificateConfig config;
    private X509Context context;

    @BeforeEach
    public void setUp() {
        publicKey = new X509Ed448PublicKey();
        config = new X509CertificateConfig();
        context = new X509Context(config);
        chooser = new X509Chooser(config, context);
        preparator = new Ed448PublicKeyPreparator(chooser, publicKey);
    }

    @Test
    public void testPrepareWithDefaultKey() {
        preparator.prepare();

        assertNotNull(publicKey.getContent());
        assertNotNull(publicKey.getContent().getValue());
        // Ed448 public keys are 57 bytes
        assertArrayEquals(
                config.getDefaultSubjectEd448PublicKey(), publicKey.getContent().getValue());
    }

    @Test
    public void testPrepareWithCustomKey() {
        byte[] customKey =
                ArrayConverter.hexStringToByteArray(
                        "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180");
        context.setSubjectEd448PublicKey(customKey);

        preparator.prepare();

        assertNotNull(publicKey.getContent());
        assertNotNull(publicKey.getContent().getValue());
        assertArrayEquals(customKey, publicKey.getContent().getValue());
    }
}
