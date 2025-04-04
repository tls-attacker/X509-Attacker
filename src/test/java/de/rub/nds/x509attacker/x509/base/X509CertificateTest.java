/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.base;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.NamedEllipticCurveParameters;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.handler.X509CertificateHandler;
import de.rub.nds.x509attacker.x509.handler.X509Handler;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import de.rub.nds.x509attacker.x509.model.publickey.X509EcdhEcdsaPublicKey;
import de.rub.nds.x509attacker.x509.parser.X509Parser;
import de.rub.nds.x509attacker.x509.preparator.X509CertificatePreparator;
import de.rub.nds.x509attacker.x509.preparator.X509Preparator;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class X509CertificateTest {

    private X509Certificate ecCertificate;

    private X509Chooser chooser;

    @BeforeEach
    public void setup() {
        ecCertificate = new X509Certificate("test");
        this.chooser = new X509Chooser(new X509CertificateConfig(), new X509Context());
        X509Parser parser = ecCertificate.getParser(chooser);
        parser.parse(
                new BufferedInputStream(
                        new ByteArrayInputStream(
                                ArrayConverter.hexStringToByteArray(
                                        "3082048b30820373a00302010202103557d197c2667ef80ac5ac0742ea9013300d06092a864886f70d01010b05003046310b300906035504061302555331223020060355040a1319476f6f676c65205472757374205365727669636573204c4c43311330110603550403130a47545320434120314333301e170d3233303330363038323030335a170d3233303532393038323030325a30163114301206035504030c0b2a2e676f6f676c652e64653059301306072a8648ce3d020106082a8648ce3d030107034200045edd28a3382c5e95830513ce0a97fb302b00f323ce8043f3a54870d069b77f61e8d07debb1b7f4f52a55b1981f1e73c6a67cfc1a0e259a1247cf87280899da3ca382026e3082026a300e0603551d0f0101ff04040302078030130603551d25040c300a06082b06010505070301300c0603551d130101ff04023000301d0603551d0e041604140f6019b994d494fc99e56057b637bf70f239eabd301f0603551d230418301680148a747faf85cdee95cd3d9cd0e24614f371351d27306a06082b06010505070101045e305c302706082b06010505073001861b687474703a2f2f6f6373702e706b692e676f6f672f677473316333303106082b060105050730028625687474703a2f2f706b692e676f6f672f7265706f2f63657274732f6774733163332e64657230210603551d11041a3018820b2a2e676f6f676c652e64658209676f6f676c652e646530210603551d20041a30183008060667810c010201300c060a2b06010401d679020503303c0603551d1f043530333031a02fa02d862b687474703a2f2f63726c732e706b692e676f6f672f6774733163332f7a644154743045785f466b2e63726c30820103060a2b06010401d6790204020481f40481f100ef007500e83ed0da3ef5063532e75728bc896bc903d3cbd1116beceb69e1777d6d06bd6e00000186b6388bb4000004030046304402206eaafe7140a06927700379640eb4a4a1be8358d9918e213e05eddd08994f8ad602203963c3a7fa75c3095e86d653fb40311e6b9f01973287174e37c5597090313b700076007a328c54d8b72db620ea38e0521ee98416703213854d3bd22bc13a57a352eb5200000186b6388bfe0000040300473045022100bb3811c3fd00eb0d71eab0e62e1e38a4b2d065435a93907106175bdd33ad9704022045694a7bc5dd6d6639559a44591de4f365699beadd0b7977e018776e02c47649300d06092a864886f70d01010b0500038201010089f1c0958afdccd7e6e5d71573745d513a3b808c278b0e7ecf6ff58cc173457a74d1fc8e024a738a31783b391aecc265eef69fbedcd5a89fb8bfc26a95d348d5a1b14be38e18ea4cfc4419f63bb1701e202c0751771dc4272d623476ca0abbdeb9e442c5756adf1377bc45632234bfd4f5a5a342e73e3a1d5159541b73b002ef6624354a31b95d3431807601e325b57556266a10a6328a682ef10912305f892506d3f9f4915ef794e427e106f0114562eba30b0741c41e1e5f7f95c0433ac0eb66abe4c07296525efb785b1c175d65d46d03ad5da3126bec2a4800dc696537ca28621c2877c2a37b7db688a0e7709a057762f5919de1997e43d0e1e5ba8b4106"))));
    }

    @Disabled
    @Test
    void testGetAkid() {}

    @Test
    void testGetCertificateKeyType() {
        X509PublicKeyType certificateKeyType = ecCertificate.getCertificateKeyType();
        assertTrue(certificateKeyType == X509PublicKeyType.ECDH_ECDSA);
    }

    @Test
    void testGetCommonName() {
        String commonName = ecCertificate.getSubjectCommonName();
        assertEquals("*.google.de", commonName);
    }

    @Test
    void testGetEllipticCurve() {
        assertEquals(NamedEllipticCurveParameters.SECP256R1, ecCertificate.getEllipticCurve());
    }

    @Disabled
    @Test
    void testGetExtendedKeyUsages() {}

    @Test
    void testGetHandler() {
        X509Handler handler = ecCertificate.getHandler(chooser);
        assertTrue(handler != null);
        assertTrue(handler instanceof X509CertificateHandler);
    }

    @Test
    void testGetHashAlgorithm() {
        assertEquals(HashAlgorithm.SHA256, ecCertificate.getHashAlgorithm());
    }

    @Test
    void testGetIssuerString() {
        assertEquals(
                "C=US O=Google Trust Services LLC CN=GTS CA 1C3", ecCertificate.getIssuerString());
    }

    @Disabled
    @Test
    void testGetKeyUsages() {}

    @Test
    void testGetNotAfter() {
        assertEquals(
                new DateTime(2023, 5, 29, 8, 20, 2, 0, DateTimeZone.UTC).toInstant(),
                ecCertificate.getNotAfter().toInstant());
    }

    @Test
    void testGetNotBefore() {
        assertEquals(
                new DateTime(2023, 3, 6, 8, 20, 3, 0, DateTimeZone.UTC).toInstant(),
                ecCertificate.getNotBefore().toInstant());
    }

    @Test
    void testGetPreparator() {
        X509Preparator preparator = ecCertificate.getPreparator(chooser);
        assertTrue(preparator != null);
        assertTrue(preparator instanceof X509CertificatePreparator);
    }

    @Test
    void testGetPublicKey() {
        assertTrue(ecCertificate.getPublicKey() instanceof X509EcdhEcdsaPublicKey);
        assertEquals(
                ecCertificate.getPublicKey().getX509PublicKeyType(), X509PublicKeyType.ECDH_ECDSA);
    }

    @Test
    void testGetPublicKeyContainer() {}

    @Test
    void testGetPublicParameters() {}

    @Test
    void testGetSerializer() {}

    @Test
    void testGetSha256Fingerprint() {}

    @Test
    void testGetSignature() {}

    @Test
    void testGetSignatureAlgorithm() {}

    @Test
    void testGetSignatureAlgorithmIdentifier() {}

    @Test
    void testGetSignatureComputations() {}

    @Disabled
    @Test
    void testGetSkid() {}

    @Disabled
    @Test
    void testGetSubjectAlternativeNames() {}

    @Test
    void testGetSubjectString() {}

    @Test
    void testGetTbsCertificate() {}

    @Test
    void testGetX509Version() {}

    @Disabled
    @Test
    void testHasCertificateRevocationList() {}

    @Disabled
    @Test
    void testHasExtendedKeyUsageExtension() {}

    @Disabled
    @Test
    void testHasOcsp() {}

    @Disabled
    @Test
    void testHasSanExtension() {}

    @Disabled
    @Test
    void testHasSignedCertificateTransparencyEntry() {}

    @Disabled
    @Test
    void testHasWeakBlacklistedDebianKey() {}

    @Test
    void testIsCommonNameValidForUri() {}

    @Test
    void testIsEllipticCurveCertificate() {}

    @Test
    void testIsExpired() {}

    @Test
    void testIsIpOrDomain() {}

    @Test
    void testIsLeaf() {}

    @Disabled
    @Test
    void testIsOcspMustStaple() {}

    @Disabled
    @Test
    void testIsRevokedCrl() {}

    @Disabled
    @Test
    void testIsRevokedOcsp() {}

    @Disabled
    @Test
    void testIsSanValidForUri() {}

    @Test
    void testIsSelfSigned() {}

    @Test
    void testIsValidLeafForUri() {}

    @Test
    void testIsYetValid() {}

    @Test
    void testSetSignature() {}

    @Test
    void testSetSignatureAlgorithmIdentifier() {}

    @Test
    void testSetSignatureComputations() {}

    @Test
    void testSetTbsCertificate() {}
}
