/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.preparator;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.asn1.parser.Asn1FieldParser;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.base.X509Certificate;
import java.io.ByteArrayInputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class X509CertificatePreparatorTest {

    private static final Logger LOGGER = LogManager.getLogger();

    private X509CertificatePreparator instance;

    /** Test of prepareContent method, of class X509CertificatePreparator. */
    @Test
    public void testCreationSerialisationParsingSerialisationEquality() {
        X509CertificateConfig config = new X509CertificateConfig();
        X509Chooser chooser = new X509Chooser(config, new X509Context());
        X509Certificate x509Certificate = new X509Certificate("leafCertificate", chooser.getConfig());
        instance = new X509CertificatePreparator(x509Certificate, chooser);
        instance.prepare();
        byte[] serializedCertificate = x509Certificate.getGenericSerializer().serialize();
        LOGGER.info(ArrayConverter.bytesToHexString(serializedCertificate));
        X509Certificate secondX509Certificate = new X509Certificate("x509Certificate");
        secondX509Certificate.getParser().parse(new ByteArrayInputStream(serializedCertificate));
        byte[] secondSerialization = secondX509Certificate.getGenericSerializer().serialize();
        Assertions.assertArrayEquals(serializedCertificate, secondSerialization);
    }

    @Test
    public void testPublicCertificateParsing() {
        X509Certificate x509Certificate = new X509Certificate("x509Certificate");
        Asn1FieldParser<Asn1Sequence> parser = x509Certificate.getParser();
        parser.parse(
                new ByteArrayInputStream(
                        ArrayConverter.hexStringToByteArray(
                                "308202123082017ba00302010202143534b7b44c73efe2449091e3e6c568d88ad402d0300d06092a864886f70d01010b0500301b3119301706035504030c10746c732d61747461636b65722e636f6d301e170d3232313030343035353135315a170d3238303332363035353135315a301b3119301706035504030c10746c732d61747461636b65722e636f6d30819f300d06092a864886f70d010101050003818d0030818902818100d7a8a3f1e45fe35496ea763d68c07d384db1c5cd20c9fc40247430ae3e2fa68922f99a94261fba5fbf0cf68854c8835b77c034a8d433a95272f3b432dcefdbae3ac473e5c1e18f5a5ee7bd8726671bd8f94415c6537b8fa35635739883b96cf0d26dee77aae7f8c0fcb1e691f860915fd002eafb2b67d4aa81af800ff86aa5410203010001a3533051301d0603551d0e0416041445e0e6b3b523b4cc20fe953bfb1298f8571987a3301f0603551d2304183016801445e0e6b3b523b4cc20fe953bfb1298f8571987a3300f0603551d130101ff040530030101ff300d06092a864886f70d01010b05000381810038d4789691832082910c4a01e7331a45a98e2829f102a0d08406ea84e2de4a48e182a13cd103ffbdf8846ce50e4172bd4d43dffb9d04f55140561baaa9002d4a7bc244647993252261b9e2165e795211d14ca64b7e91671f90d3584371431942954319ec7bd52fc8110db8706c68cc917ba128ec124c8e944e2e360b1f4678bc")));
    }

    @Test
    public void testPublicCertificateEcdsaParsing() {
        X509Certificate x509Certificate = new X509Certificate("x509Certificate");
        Asn1FieldParser<Asn1Sequence> parser = x509Certificate.getParser();
        parser.parse(
                new ByteArrayInputStream(
                        ArrayConverter.hexStringToByteArray(
                                "308201883082012ea00302010202143327723cb07ea52c2ddd7fa5b1802fca177a45ec300a06082a8648ce3d040302301b3119301706035504030c10746c732d61747461636b65722e636f6d301e170d3232313030343035353135315a170d3238303332363035353135315a301b3119301706035504030c10746c732d61747461636b65722e636f6d3056301006072a8648ce3d020106052b8104000a03420004191829ec3018d23072658aea338fb8679d546fefdfb8aac7d2384f12774772e0ee2ae5150819cc178dd84ba09687d11f9ee1b79295a5fc5a989d021694ca01a3a3533051301d0603551d0e041604141cd522db7b18d25bdbd379069a0ce63acbb89629301f0603551d230418301680141cd522db7b18d25bdbd379069a0ce63acbb89629300f0603551d130101ff040530030101ff300a06082a8648ce3d040302034800304502201cdc6121548180f271e8171875c5f3863b2f8147e8d8c034102b99fcdcae19ad022100f0d62fa3d99e8974da2b66321ac17e67f26dd3404b5233d43701e2008a225a0e")));
    }
}
