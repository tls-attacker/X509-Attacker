/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509.handler.publickey.parameters;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import de.rub.nds.x509attacker.x509.model.publickey.parameters.X509EcNamedCurveParameters;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class X509EcNamedCurveParametersHandlerTest {

    // EC certificate (*.google.de, P-256 / secp256r1)
    private static final String EC_CERT_HEX =
            "3082048b30820373a00302010202103557d197c2667ef80ac5ac0742ea9013300d06092a864886f70d01010b05003046310b3009060355040613025553312230200603550"
                    + "40a1319476f6f676c65205472757374205365727669636573204c4c4331133011060355040313"
                    + "0a47545320434120314333301e170d3233303330363038323030335a170d323330353239303832"
                    + "3030325a30163114301206035504030c0b2a2e676f6f676c652e646530593013060"
                    + "72a8648ce3d020106082a8648ce3d030107034200045edd28a3382c5e95830513ce0a97fb302b00f"
                    + "323ce8043f3a54870d069b77f61e8d07debb1b7f4f52a55b1981f1e73c6a67cfc1a0e259a1247cf8"
                    + "7280899da3ca382026e3082026a300e0603551d0f0101ff04040302078030130603551d25040c300"
                    + "a06082b06010505070301300c0603551d130101ff04023000301d0603551d0e041604140f6019b99"
                    + "4d494fc99e56057b637bf70f239eabd301f0603551d230418301680148a747faf85cdee95cd3d9cd"
                    + "0e24614f371351d27306a06082b06010505070101045e305c302706082b06010505073001861b687"
                    + "474703a2f2f6f6373702e706b692e676f6f672f677473316333303106082b0601050507300286256"
                    + "87474703a2f2f706b692e676f6f672f7265706f2f63657274732f6774733163332e6465723021060"
                    + "3551d11041a3018820b2a2e676f6f676c652e64658209676f6f676c652e646530210603551d20041"
                    + "a30183008060667810c010201300c060a2b06010401d679020503303c0603551d1f043530333031a"
                    + "02fa02d862b687474703a2f2f63726c732e706b692e676f6f672f6774733163332f7a64415474304"
                    + "5785f466b2e63726c30820103060a2b06010401d6790204020481f40481f100ef007500e83ed0da3"
                    + "ef5063532e75728bc896bc903d3cbd1116beceb69e1777d6d06bd6e00000186b6388bb4000004030"
                    + "046304402206eaafe7140a06927700379640eb4a4a1be8358d9918e213e05eddd08994f8ad602203"
                    + "963c3a7fa75c3095e86d653fb40311e6b9f01973287174e37c5597090313b700076007a328c54d8b"
                    + "72db620ea38e0521ee98416703213854d3bd22bc13a57a352eb5200000186b6388bfe00000403004"
                    + "73045022100bb3811c3fd00eb0d71eab0e62e1e38a4b2d065435a93907106175bdd33ad970402204"
                    + "5694a7bc5dd6d6639559a44591de4f365699beadd0b7977e018776e02c47649300d06092a864886f"
                    + "70d01010b0500038201010089f1c0958afdccd7e6e5d71573745d513a3b808c278b0e7ecf6ff58cc"
                    + "173457a74d1fc8e024a738a31783b391aecc265eef69fbedcd5a89fb8bfc26a95d348d5a1b14be38"
                    + "e18ea4cfc4419f63bb1701e202c0751771dc4272d623476ca0abbdeb9e442c5756adf1377bc45632"
                    + "234bfd4f5a5a342e73e3a1d5159541b73b002ef6624354a31b95d3431807601e325b57556266a10a"
                    + "6328a682ef10912305f892506d3f9f4915ef794e427e106f0114562eba30b0741c41e1e5f7f95c04"
                    + "33ac0eb66abe4c07296525efb785b1c175d65d46d03ad5da3126bec2a4800dc696537ca28621c287"
                    + "7c2a37b7db688a0e7709a057762f5919de1997e43d0e1e5ba8b4106";

    private X509EcNamedCurveParameters ecParams;

    @BeforeEach
    public void setup() {
        // Parse the EC certificate to obtain the X509EcNamedCurveParameters instance
        X509Context parseContext = new X509Context();
        X509Chooser parseChooser = parseContext.getChooser();
        X509Certificate cert = new X509Certificate("cert");
        cert.getParser(parseChooser)
                .parse(
                        new BufferedInputStream(
                                new ByteArrayInputStream(
                                        DataConverter.hexStringToByteArray(EC_CERT_HEX))));
        ecParams = (X509EcNamedCurveParameters) cert.getPublicParameters();
    }

    /**
     * Verifies that adjustContext() sets SubjectPublicKeyType to ECDH_ECDSA. This was missing
     * before the fix: only setSubjectNamedCurve() was called, leaving SubjectPublicKeyType null so
     * PublicKeyBitStringParser fell back to the RSA config default.
     */
    @Test
    void testAdjustContextSetsSubjectPublicKeyType() {
        X509Context freshContext = new X509Context();
        X509Chooser freshChooser = freshContext.getChooser();

        new X509EcNamedCurveParametersHandler(freshChooser, ecParams).adjustContext();

        assertEquals(X509PublicKeyType.ECDH_ECDSA, freshContext.getSubjectPublicKeyType());
    }

    /** Verifies that adjustContext() also sets the named curve (pre-existing behaviour). */
    @Test
    void testAdjustContextSetsNamedCurve() {
        X509Context freshContext = new X509Context();
        X509Chooser freshChooser = freshContext.getChooser();

        new X509EcNamedCurveParametersHandler(freshChooser, ecParams).adjustContext();

        assertNotNull(freshContext.getSubjectNamedCurve());
        assertEquals(X509NamedCurve.SECP256R1, freshContext.getSubjectNamedCurve());
    }
}
