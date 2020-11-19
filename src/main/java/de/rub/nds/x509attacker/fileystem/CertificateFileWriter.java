/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.x509attacker.fileystem;

import de.rub.nds.asn1tool.filesystem.BinaryFileWriter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class CertificateFileWriter {

    public static final String CERTIFICATE_PEM_PREFIX = "-----BEGIN CERTIFICATE-----\n";

    public static final String CERTIFICATE_PEM_SUFFIX = "\n-----END CERTIFICATE-----\n";

    private final BinaryFileWriter binaryFileWriter;

    public CertificateFileWriter(final String filename) throws IOException {
        this.binaryFileWriter = new BinaryFileWriter(filename);
    }

    public CertificateFileWriter(final String directory, final String filename) throws IOException {
        this.binaryFileWriter = new BinaryFileWriter(directory, filename);
    }

    public void writeCertificate(final byte[] certificateBytes) throws IOException {
        this.writeCertificate(new String(Base64.getEncoder().encode(certificateBytes), StandardCharsets.UTF_8));
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
