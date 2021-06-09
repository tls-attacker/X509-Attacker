/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.filesystem;

import de.rub.nds.asn1tool.filesystem.BinaryFileWriter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class CertificateFileWriter {

    public static final String CERTIFICATE_PEM_PREFIX = "-----BEGIN CERTIFICATE-----\r\n";

    public static final String CERTIFICATE_PEM_SUFFIX = "\r\n-----END CERTIFICATE-----\r\n";

    private final BinaryFileWriter binaryFileWriter;

    public CertificateFileWriter(final String filename) throws IOException {
        this.binaryFileWriter = new BinaryFileWriter(filename);
    }

    public CertificateFileWriter(final String directory, final String filename) throws IOException {
        this.binaryFileWriter = new BinaryFileWriter(directory, filename);
    }

    public void writeCertificate(final byte[] certificateBytes) throws IOException {
        this.writeCertificate(
            new String(Base64.getMimeEncoder(64, "\r\n".getBytes()).encode(certificateBytes), StandardCharsets.UTF_8));
    }

    public void writeCertificate(final String certificateBase64String) throws IOException {
        this.binaryFileWriter.write(CERTIFICATE_PEM_PREFIX.getBytes());
        this.binaryFileWriter.write(certificateBase64String.getBytes());
        this.binaryFileWriter.write(CERTIFICATE_PEM_SUFFIX.getBytes());
    }

    public void close() throws IOException {
        this.binaryFileWriter.close();
    }
}
