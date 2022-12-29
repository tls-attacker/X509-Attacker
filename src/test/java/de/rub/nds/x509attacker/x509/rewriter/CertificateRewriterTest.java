/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.rewriter;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.Asn1FieldParser;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.base.X509Certificate;
import de.rub.nds.x509attacker.x509.base.publickey.PublicKeyBitString;
import de.rub.nds.x509attacker.x509.preparator.X509CertificatePreparator;
import java.io.ByteArrayInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class CertificateRewriterTest {

    private static final Logger LOGGER = LogManager.getLogger();

    public CertificateRewriterTest() {}

    @Test
    public void testRewriteCertificate() {
        X509Certificate x509Certificate = new X509Certificate("x509Certificate");

        X509Chooser chooser = new X509Chooser(new X509CertificateConfig(), new X509Context());

        Asn1FieldParser<Asn1Sequence> parser = x509Certificate.getParser();
        byte[] originalCertificate =
                ArrayConverter.hexStringToByteArray(
                        "308202123082017ba00302010202143534b7b44c73efe2449091e3e6c568d88ad402d0300d06092a864886f70d01010b0500301b3119301706035504030c10746c732d61747461636b65722e636f6d301e170d3232313030343035353135315a170d3238303332363035353135315a301b3119301706035504030c10746c732d61747461636b65722e636f6d30819f300d06092a864886f70d010101050003818d0030818902818100d7a8a3f1e45fe35496ea763d68c07d384db1c5cd20c9fc40247430ae3e2fa68922f99a94261fba5fbf0cf68854c8835b77c034a8d433a95272f3b432dcefdbae3ac473e5c1e18f5a5ee7bd8726671bd8f94415c6537b8fa35635739883b96cf0d26dee77aae7f8c0fcb1e691f860915fd002eafb2b67d4aa81af800ff86aa5410203010001a3533051301d0603551d0e0416041445e0e6b3b523b4cc20fe953bfb1298f8571987a3301f0603551d2304183016801445e0e6b3b523b4cc20fe953bfb1298f8571987a3300f0603551d130101ff040530030101ff300d06092a864886f70d01010b05000381810038d4789691832082910c4a01e7331a45a98e2829f102a0d08406ea84e2de4a48e182a13cd103ffbdf8846ce50e4172bd4d43dffb9d04f55140561baaa9002d4a7bc244647993252261b9e2165e795211d14ca64b7e91671f90d3584371431942954319ec7bd52fc8110db8706c68cc917ba128ec124c8e944e2e360b1f4678bc");
        parser.parse(new ByteArrayInputStream(originalCertificate));
        CertificateRewriter rewriter = new CertificateRewriter();
        rewriter.fixateNonContainerContent(x509Certificate);
        X509CertificatePreparator preparator =
                new X509CertificatePreparator(x509Certificate, chooser);
        preparator.prepare();
        byte[] serializedCertificate = x509Certificate.getGenericSerializer().serialize();
        LOGGER.info("Reserialized cert: " + ArrayConverter.bytesToHexString(serializedCertificate));
        Assertions.assertArrayEquals(originalCertificate, serializedCertificate);

        x509Certificate.getSignature().getContent().setModification(null);
        x509Certificate
                .getTbsCertificate()
                .getSubjectPublicKeyInfo()
                .setSubjectPublicKeyBitString(new PublicKeyBitString("subjectPublicKey"));
        preparator = new X509CertificatePreparator(x509Certificate, chooser);
        preparator.prepare();
        serializedCertificate = x509Certificate.getGenericSerializer().serialize();
        LOGGER.info(
                "With new signature and public key: "
                        + ArrayConverter.bytesToHexString(serializedCertificate));
    }
}
