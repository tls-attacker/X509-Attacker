/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.filesystem;

import de.rub.nds.x509attacker.x509.base.X509Certificate;
import de.rub.nds.x509attacker.x509.base.X509CertificateChain;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Base64;
import java.util.function.Consumer;

public class CertificateFileReader {

    public static final String CERTIFICATE_PEM_PREFIX = "-----BEGIN CERTIFICATE-----";

    public static final String CERTIFICATE_PEM_SUFFIX = "-----END CERTIFICATE-----";

    private CertificateFileReader() {}

    public static X509CertificateChain readBytes(File file) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(file));

        X509CertificateChain chain = new X509CertificateChain();
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
                                    X509Certificate x509Certificate =
                                            new X509Certificate("x509Certificate");
                                    x509Certificate
                                            .getParser()
                                            .parse(new ByteArrayInputStream(certificateBytes));
                                    chain.addCertificate(x509Certificate);
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
        return chain;
    }
}
