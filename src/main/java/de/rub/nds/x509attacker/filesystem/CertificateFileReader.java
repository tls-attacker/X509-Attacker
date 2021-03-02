/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.filesystem;

import de.rub.nds.asn1tool.filesystem.TextFileReader;

import java.io.IOException;
import java.util.Base64;

public class CertificateFileReader extends TextFileReader {

    public static final String CERTIFICATE_PEM_PREFIX = "-----BEGIN CERTIFICATE-----";

    public static final String CERTIFICATE_PEM_SUFFIX = "-----END CERTIFICATE-----";

    public CertificateFileReader(final String filename) {
        super("", filename);
    }

    public byte[] readBytes() throws IOException {
        byte[] bytes = null;
        String certificateFileContent = super.read();
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
