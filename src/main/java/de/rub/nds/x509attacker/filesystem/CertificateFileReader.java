/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509attacker.filesystem;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Base64;

public class CertificateFileReader {

    public static final String CERTIFICATE_PEM_PREFIX = "-----BEGIN CERTIFICATE-----";

    public static final String CERTIFICATE_PEM_SUFFIX = "-----END CERTIFICATE-----";

    private final File file;

    public CertificateFileReader(final File file) {
        this.file = file;
    }

    public byte[] readBytes() throws IOException {
        FileInputStream stream = new FileInputStream(file);
        byte[] bytes = stream.readAllBytes();
        String certificateFileContent = new String(bytes);
        if (certificateFileContent.contains(CERTIFICATE_PEM_PREFIX)
                && certificateFileContent.contains(CERTIFICATE_PEM_SUFFIX)) {
            String base64Str = certificateFileContent.replace("\\n", "").replace("\n", "").replace("\r", "")
                    .replace(CERTIFICATE_PEM_PREFIX, "").replace(CERTIFICATE_PEM_SUFFIX, "").trim();
            bytes = Base64.getDecoder().decode(base64Str);
        }
        if (bytes == null) {
            throw new IOException("File is not a PEM-encoded certificate file!");
        }
        return bytes;
    }
}
