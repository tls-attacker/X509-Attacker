/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.x509;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.base.X509Certificate;
import de.rub.nds.x509attacker.x509.base.X509CertificateChain;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.jupiter.api.Test;

public class X509CertificateChainBuidlerTest {

    private static final Logger LOGGER = LogManager.getLogger();

    /** Test of buildChain method, of class X509CertificateChainBuidler. */
    @Test
    public void testBuildChain() {
        X509CertificateConfig rootConfig = new X509CertificateConfig();
        List<ImmutablePair<X500AttributeType, String>> subject = new LinkedList<>();
        subject.add(new ImmutablePair<>(X500AttributeType.COMMON_NAME, "TLS-Attacker CA"));
        rootConfig.setSubject(subject);
        rootConfig.setDefaultIssuer(subject);
        rootConfig.setRsaPrivateKey(new BigInteger("12345"));
        rootConfig.setNotBefore(new DateTime(1990, 9, 14, 3, 24, DateTimeZone.UTC));
        rootConfig.setNotAfter(new DateTime(2040, 9, 14, 3, 24, DateTimeZone.UTC));
        byte[] serialNumber =
                ArrayConverter.hexStringToByteArray("FFAAFFAAFFAAFFAAFFAAFFAAFFAAFFAAFFAAFFAA");
        rootConfig.setSerialNumber(new BigInteger(serialNumber));
        rootConfig.setRsaModulus(new BigInteger("AABBCCAABBCCAABBCC", 16));
        rootConfig.setRsaPublicKey(new BigInteger("03", 16));

        X509CertificateConfig intermediateConfig = new X509CertificateConfig();
        subject = new LinkedList<>();
        subject.add(new ImmutablePair<>(X500AttributeType.COMMON_NAME, "TLS-Attacker Inter. CA"));
        intermediateConfig.setSubject(subject);

        intermediateConfig.setRsaPrivateKey(new BigInteger("54321"));
        intermediateConfig.setNotBefore(new DateTime(2022, 1, 1, 12, 13, DateTimeZone.UTC));
        intermediateConfig.setNotAfter(new DateTime(2030, 9, 4, 3, 13, DateTimeZone.UTC));
        serialNumber =
                ArrayConverter.hexStringToByteArray("2211221122112211221122112211221122112211");
        intermediateConfig.setSerialNumber(new BigInteger(serialNumber));
        intermediateConfig.setRsaModulus(
                new BigInteger(
                        "123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456123456",
                        16));
        intermediateConfig.setRsaPublicKey(new BigInteger("FFFFFF", 16));

        X509CertificateConfig leafConfig = new X509CertificateConfig();
        subject = new LinkedList<>();
        subject.add(new ImmutablePair<>(X500AttributeType.COMMON_NAME, "tii.ae"));
        leafConfig.setSubject(subject);
        leafConfig.setRsaPrivateKey(new BigInteger("33333"));
        leafConfig.setNotBefore(new DateTime(2021, 7, 5, 22, 30, DateTimeZone.UTC));
        leafConfig.setNotAfter(new DateTime(2023, 7, 5, 22, 30, DateTimeZone.UTC));
        serialNumber =
                ArrayConverter.hexStringToByteArray("FF11FF11FF11FF11FF11FF11FF11FF11FF11FF11");
        leafConfig.setSerialNumber(new BigInteger(serialNumber));
        leafConfig.setRsaModulus(
                new BigInteger(
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                        16));
        leafConfig.setRsaPublicKey(new BigInteger("01", 16));

        X509CertificateChainBuidler builder = new X509CertificateChainBuidler();

        X509CertificateChain chain = builder.buildChain(rootConfig, intermediateConfig, leafConfig);
        for (X509Certificate cert : chain.getCertificateList()) {
            LOGGER.info(
                    "Cert: " + ArrayConverter.bytesToHexString(cert.getSerializer().serialize()));
        }
    }
}
