/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import java.math.BigInteger;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.jupiter.api.Test;

public class X509CertificateChainBuilderTest {

    private static final Logger LOGGER = LogManager.getLogger();

    /** Test of buildChain method, of class X509CertificateChainBuidler. */
    @Test
    public void testBuildChain() {
        Security.addProvider(new BouncyCastleProvider());
        X509CertificateConfig rootConfig = new X509CertificateConfig();
        List<Pair<X500AttributeType, String>> subject = new LinkedList<>();
        subject.add(new Pair<>(X500AttributeType.COMMON_NAME, "TLS-Attacker CA"));
        rootConfig.setSubject(subject);
        rootConfig.setIssuer(subject);
        rootConfig.setDefaultSubjectRsaPrivateKey(new BigInteger("12345"));
        rootConfig.setNotBefore(new DateTime(1990, 9, 14, 3, 24, DateTimeZone.UTC));
        rootConfig.setNotAfter(new DateTime(2040, 9, 14, 3, 24, DateTimeZone.UTC));
        byte[] serialNumber =
                ArrayConverter.hexStringToByteArray("FFAAFFAAFFAAFFAAFFAAFFAAFFAAFFAAFFAAFFAA");
        rootConfig.setSerialNumber(new BigInteger(serialNumber));
        rootConfig.setDefaultSubjectRsaModulus(new BigInteger("AABBCCAABBCCAABBCC", 16));
        rootConfig.setDefaultSubjectRsaPublicKey(new BigInteger("03", 16));

        X509CertificateConfig intermediateConfig = new X509CertificateConfig();
        subject = new LinkedList<>();
        subject.add(new Pair<>(X500AttributeType.COMMON_NAME, "TLS-Attacker Inter. CA"));
        intermediateConfig.setSubject(subject);

        intermediateConfig.setDefaultSubjectRsaPrivateKey(new BigInteger("54321"));
        intermediateConfig.setNotBefore(new DateTime(2022, 1, 1, 12, 13, DateTimeZone.UTC));
        intermediateConfig.setNotAfter(new DateTime(2030, 9, 4, 3, 13, DateTimeZone.UTC));
        serialNumber =
                ArrayConverter.hexStringToByteArray("2211221122112211221122112211221122112211");
        intermediateConfig.setSerialNumber(new BigInteger(serialNumber));
        intermediateConfig.setDefaultSubjectRsaModulus(
                new BigInteger(
                        "123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456",
                        16));
        intermediateConfig.setDefaultSubjectRsaPublicKey(new BigInteger("FFFFFF", 16));

        X509CertificateConfig leafConfig = new X509CertificateConfig();
        subject = new LinkedList<>();
        subject.add(new Pair<>(X500AttributeType.COMMON_NAME, "leaf-cert.ae"));
        leafConfig.setSubject(subject);
        leafConfig.setDefaultSubjectRsaPrivateKey(new BigInteger("33333"));
        leafConfig.setNotBefore(new DateTime(2021, 7, 5, 22, 30, DateTimeZone.UTC));
        leafConfig.setNotAfter(new DateTime(2023, 7, 5, 22, 30, DateTimeZone.UTC));
        serialNumber =
                ArrayConverter.hexStringToByteArray("FF11FF11FF11FF11FF11FF11FF11FF11FF11FF11");
        leafConfig.setSerialNumber(new BigInteger(serialNumber));
        leafConfig.setDefaultSubjectRsaModulus(
                new BigInteger(
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                        16));
        leafConfig.setDefaultSubjectRsaPublicKey(new BigInteger("01", 16));

        X509CertificateChainBuilder builder = new X509CertificateChainBuilder();

        X509CertificateChain chain =
                builder.buildChain(rootConfig, intermediateConfig, leafConfig)
                        .getCertificateChain();
        for (X509Certificate cert : chain.getCertificateList()) {
            LOGGER.info( // TODO not sure we can pass null here
                    "Cert: "
                            + ArrayConverter.bytesToHexString(
                                    cert.getSerializer(null).serialize()));
        }
    }
}
