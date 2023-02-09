/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.filesystem;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.base.X509Certificate;
import de.rub.nds.x509attacker.x509.base.X509CertificateChain;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.cert.CertificateEncodingException;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import java.util.function.Consumer;
import org.bouncycastle.crypto.tls.Certificate;

public class CertificateIo {

    private static final String CERTIFICATE_PEM_PREFIX = "-----BEGIN CERTIFICATE-----";

    private static final String CERTIFICATE_PEM_SUFFIX = "-----END CERTIFICATE-----";

    private CertificateIo() {}

    public static X509CertificateChain readPemChain(File file) throws IOException {
        return readPemChain(new FileInputStream(file));
    }

    public static X509CertificateChain readPemChain(InputStream inputStream) throws IOException {
        X509Chooser chooser = new X509Chooser(new X509CertificateConfig(), new X509Context());
        X509CertificateChain chain = new X509CertificateChain();
        List<CertificateBytes> byteList = readPemCertificateByteList(inputStream);
        for (CertificateBytes certificateBytes : byteList) {
            X509Certificate x509Certificate = new X509Certificate("x509Certificate");
            x509Certificate
                    .getParser(chooser)
                    .parse(new ByteArrayInputStream(certificateBytes.getBytes()));
            chain.addCertificate(x509Certificate);
        }
        return chain;
    }

    public static List<CertificateBytes> readPemCertificateByteList(InputStream inputStream)
            throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        List<CertificateBytes> byteList = new LinkedList<>();
        reader.lines()
                .forEach(
                        new Consumer<String>() {
                            private ByteArrayOutputStream stream = null;

                            @Override
                            public void accept(String line) {
                                if (line.contains(CERTIFICATE_PEM_PREFIX)) {
                                    stream = new ByteArrayOutputStream();
                                } else if (line.contains(CERTIFICATE_PEM_SUFFIX)) {
                                    if (stream == null) {
                                        throw new RuntimeException(
                                                "Could not parse certificate chain");
                                    }
                                    byte[] certificateBytes =
                                            Base64.getDecoder().decode(stream.toByteArray());
                                    byteList.add(new CertificateBytes(certificateBytes));
                                    stream = null;
                                } else {
                                    try {
                                        if (stream == null) {
                                            throw new RuntimeException(
                                                    "Could not parse certificate chain");
                                        }
                                        stream.write(line.strip().getBytes());
                                    } catch (IOException ex) {
                                        throw new RuntimeException(ex);
                                    }
                                }
                            }
                        });
        return byteList;
    }

    public static X509CertificateChain readRawChain(InputStream inputStream) throws IOException {
        X509CertificateChain chain = new X509CertificateChain();

        // Outer length field
        byte[] lengthField = new byte[3];
        inputStream.read(lengthField);
        int outLength = ArrayConverter.bytesToInt(lengthField);
        ByteArrayInputStream subCertificateListStream =
                new ByteArrayInputStream(inputStream.readNBytes(outLength));
        while (subCertificateListStream.available() > 0) {
            chain.addCertificate(readRawCertificate(subCertificateListStream));
        }
        return chain;
    }

    public static X509CertificateChain readRawCertificateAsChain(InputStream inputStream)
            throws IOException {
        X509Chooser chooser = new X509Chooser(new X509CertificateConfig(), new X509Context());
        byte[] lengthField = new byte[3];
        inputStream.read(lengthField);
        int length = ArrayConverter.bytesToInt(lengthField);
        ByteArrayInputStream certificateInputStream =
                new ByteArrayInputStream(inputStream.readNBytes(length));
        X509Certificate certificate = new X509Certificate("certificate");
        certificate.getParser(chooser).parse(certificateInputStream);
        X509CertificateChain chain = new X509CertificateChain();
        chain.addCertificate(certificate);
        return chain;
    }

    public static X509Certificate readRawCertificate(InputStream inputStream) throws IOException {
        X509Chooser chooser = new X509Chooser(new X509CertificateConfig(), new X509Context());
        byte[] lengthField = new byte[3];
        inputStream.read(lengthField);
        int length = ArrayConverter.bytesToInt(lengthField);
        ByteArrayInputStream certificateInputStream =
                new ByteArrayInputStream(inputStream.readNBytes(length));
        X509Certificate certificate = new X509Certificate("certificate");
        certificate.getParser(chooser).parse(certificateInputStream);
        return certificate;
    }

    public static X509CertificateChain convert(Certificate certificateList) {
        X509Chooser chooser = new X509Chooser(new X509CertificateConfig(), new X509Context());
        try {
            X509CertificateChain chain = new X509CertificateChain();
            for (org.bouncycastle.asn1.x509.Certificate certificate :
                    certificateList.getCertificateList()) {
                ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                certificate.encodeTo(outputStream);
                X509Certificate x509Certificate = new X509Certificate("certificate");
                x509Certificate
                        .getParser(chooser)
                        .parse(new ByteArrayInputStream(outputStream.toByteArray()));
                chain.addCertificate(x509Certificate);
            }
            return chain;
        } catch (IOException ex) {
            throw new RuntimeException("Could not convert certificate");
        }
    }

    public static X509CertificateChain convert(java.security.cert.Certificate certificate) {
        X509Chooser chooser = new X509Chooser(new X509CertificateConfig(), new X509Context());
        try {
            X509CertificateChain chain = new X509CertificateChain();
            X509Certificate x509Certificate = new X509Certificate("certificate");
            x509Certificate
                    .getParser(chooser)
                    .parse(new ByteArrayInputStream(certificate.getEncoded()));
            chain.addCertificate(x509Certificate);
            return chain;
        } catch (CertificateEncodingException ex) {
            throw new RuntimeException("Could not convert certificate");
        }
    }
}
