/*
 * X.509-Attacker - A Library for Arbitrary X.509 Certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.filesystem;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.protocol.util.SilentByteArrayOutputStream;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
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
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.crypto.TlsCertificate;

public class CertificateIo {

    private static final String CERTIFICATE_PEM_PREFIX = "-----BEGIN CERTIFICATE-----";

    private static final String CERTIFICATE_PEM_SUFFIX = "-----END CERTIFICATE-----";

    private static final int LENGTH_FIELD_BYTE_LENGTH = 3;

    private CertificateIo() {}

    public static X509CertificateChain readPemChain(File file) throws IOException {
        return readPemChain(new FileInputStream(file));
    }

    public static X509CertificateChain readPemChain(InputStream inputStream) throws IOException {
        X509Context context = new X509Context();
        X509Chooser chooser = context.getChooser();
        X509CertificateChain chain = new X509CertificateChain();
        List<CertificateBytes> byteList = readPemCertificateByteList(inputStream);
        for (CertificateBytes certificateBytes : byteList) {
            X509Certificate x509Certificate = new X509Certificate("x509Certificate");
            x509Certificate
                    .getParser(chooser)
                    .parse(
                            new BufferedInputStream(
                                    new ByteArrayInputStream(certificateBytes.getBytes())));
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
                            private SilentByteArrayOutputStream stream = null;

                            @Override
                            public void accept(String line) {
                                if (line.contains(CERTIFICATE_PEM_PREFIX)) {
                                    stream = new SilentByteArrayOutputStream();
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
                                    if (stream == null) {
                                        throw new RuntimeException(
                                                "Could not parse certificate chain");
                                    }
                                    stream.write(line.strip().getBytes());
                                }
                            }
                        });
        return byteList;
    }

    public static X509CertificateChain readRawChain(InputStream inputStream) throws IOException {
        X509CertificateChain chain = new X509CertificateChain();

        // Outer length field
        byte[] lengthField = new byte[LENGTH_FIELD_BYTE_LENGTH];
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
        X509Context context = new X509Context();
        X509Chooser chooser = context.getChooser();
        byte[] lengthField = new byte[LENGTH_FIELD_BYTE_LENGTH];
        inputStream.read(lengthField);
        int length = ArrayConverter.bytesToInt(lengthField);
        BufferedInputStream certificateInputStream =
                new BufferedInputStream(new ByteArrayInputStream(inputStream.readNBytes(length)));
        X509Certificate certificate = new X509Certificate("certificate");
        certificate.getParser(chooser).parse(certificateInputStream);
        X509CertificateChain chain = new X509CertificateChain();
        chain.addCertificate(certificate);
        return chain;
    }

    public static X509Certificate readRawCertificate(InputStream inputStream) throws IOException {
        X509Context context = new X509Context();
        X509Chooser chooser = context.getChooser();
        byte[] lengthField = new byte[LENGTH_FIELD_BYTE_LENGTH];
        inputStream.read(lengthField);
        int length = ArrayConverter.bytesToInt(lengthField);
        BufferedInputStream certificateInputStream =
                new BufferedInputStream(new ByteArrayInputStream(inputStream.readNBytes(length)));
        X509Certificate certificate = new X509Certificate("certificate");
        certificate.getParser(chooser).parse(certificateInputStream);
        return certificate;
    }

    public static X509CertificateChain convert(Certificate certificateList) {
        X509Context context = new X509Context();
        X509Chooser chooser = context.getChooser();
        try {
            X509CertificateChain chain = new X509CertificateChain();
            for (TlsCertificate certificate : certificateList.getCertificateList()) {
                SilentByteArrayOutputStream outputStream = new SilentByteArrayOutputStream();
                outputStream.write(certificate.getEncoded());
                X509Certificate x509Certificate = new X509Certificate("certificate");
                x509Certificate
                        .getParser(chooser)
                        .parse(
                                new BufferedInputStream(
                                        new ByteArrayInputStream(outputStream.toByteArray())));
                chain.addCertificate(x509Certificate);
            }
            return chain;
        } catch (IOException ex) {
            throw new RuntimeException("Could not convert certificate");
        }
    }

    public static X509CertificateChain convert(java.security.cert.Certificate certificate) {
        X509Context context = new X509Context();
        X509Chooser chooser = context.getChooser();
        try {
            X509CertificateChain chain = new X509CertificateChain();
            X509Certificate x509Certificate = new X509Certificate("certificate");
            x509Certificate
                    .getParser(chooser)
                    .parse(
                            new BufferedInputStream(
                                    new ByteArrayInputStream(certificate.getEncoded())));
            chain.addCertificate(x509Certificate);
            return chain;
        } catch (CertificateEncodingException ex) {
            throw new RuntimeException("Could not convert certificate");
        }
    }
}
