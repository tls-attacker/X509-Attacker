/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.asn1.parser;

import de.rub.nds.x509attacker.filesystem.CertificateFileReader;
import de.rub.nds.x509attacker.x509.X509Certificate;
import java.io.File;
import java.io.IOException;
import java.util.List;

public class X509Parser {

    private byte[] certificateBytes;

    public X509Parser(byte[] certificateBytes) {
        this.certificateBytes = certificateBytes;

    }

    public X509Parser(final String certificateFilePath) throws IOException {
        try {
            certificateBytes = new CertificateFileReader(certificateFilePath).readBytes();
        } catch (IOException e) {
            throw e;
        }

    }

    public X509Parser(final File certificateFile) throws IOException {
        try {
            certificateBytes = new CertificateFileReader(certificateFile.getAbsolutePath()).readBytes();
        } catch (IOException e) {
            throw e;
        }

    }

    public X509Certificate parse() throws ParserException {
        try {
            // Asn1Parser used for parsing the bytes to IntermediateAsn1Fields (without the Asn1Translator)
            List<IntermediateAsn1Field> intermediateAsn1Fields =
                new Asn1Parser(certificateBytes, false).parseIntermediateFields();
            // X509Certificate intern Translator is used for the translation from intermediateAsn1Fields to context
            // specific Asn1Fields
            X509Certificate x509certificate = X509Certificate.getInstance(intermediateAsn1Fields);
            return x509certificate;

        } catch (ParserException e) {
            throw e;
        }

    }

}
