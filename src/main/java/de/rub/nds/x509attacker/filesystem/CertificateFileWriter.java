/*
 * X509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.filesystem;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class CertificateFileWriter {

    public static final String CERTIFICATE_PEM_PREFIX = "-----BEGIN CERTIFICATE-----\r\n";

    public static final String CERTIFICATE_PEM_SUFFIX = "\r\n-----END CERTIFICATE-----\r\n";

    private final FileOutputStream outputStream;

    public CertificateFileWriter(final File file) throws IOException {
        outputStream = new FileOutputStream(file);
    }

    public void writeCertificate(final byte[] certificateBytes) throws IOException {
        this.writeCertificate(
                new String(
                        Base64.getMimeEncoder(64, "\r\n".getBytes()).encode(certificateBytes),
                        StandardCharsets.UTF_8));
    }

    public void writeCertificate(final String certificateBase64String) throws IOException {
        outputStream.write(CERTIFICATE_PEM_PREFIX.getBytes());
        outputStream.write(certificateBase64String.getBytes());
        outputStream.write(CERTIFICATE_PEM_SUFFIX.getBytes());
    }

    public void close() throws IOException {
        outputStream.close();
    }
}
