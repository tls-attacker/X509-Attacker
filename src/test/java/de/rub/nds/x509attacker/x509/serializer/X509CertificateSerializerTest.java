/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.serializer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.x509attacker.helper.X509Factory;
import de.rub.nds.x509attacker.registry.Registry;
import de.rub.nds.x509attacker.x509.X509Certificate;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Objects;

import jakarta.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class X509CertificateSerializerTest {

    @TempDir
    public File tempFolder;

    private X509Certificate x509certificate;

    public X509CertificateSerializerTest() {
    }

    @BeforeEach
    public void setUp() throws IOException, JAXBException, XMLStreamException {
        Registry.getInstance();
        x509certificate = X509Factory.getRandomX509CertificateFromFolder(new File("resources/x509Certificates"),
            new File("resources/keys"));
    }

    /**
     * Test of write method, of class X509CertificateSerializer.
     */
    @Test
    public void testWrite_File_X509Certificate() throws Exception {
        File file = new File(tempFolder, "x509CertificateWrite.tmp");
        assertTrue(file.createNewFile());
        X509CertificateSerializer.write(file, x509certificate);
    }

    /**
     * Test of write method, of class X509CertificateSerializer.
     */
    @Test
    public void testWrite_OutputStream_X509Certificate() throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        X509CertificateSerializer.write(outputStream, x509certificate);
    }

    /**
     * Test of read method, of class X509CertificateSerializer.
     */
    @Test
    public void testRead() throws Exception {
        File file = new File(tempFolder, "x509CertificateRead.tmp");
        assertTrue(file.createNewFile());
        X509CertificateSerializer.write(file, x509certificate);
        X509Certificate cert = X509CertificateSerializer.read(new FileInputStream(file));
    }

    /**
     * Test of copyX509Certificate method, of class X509CertificateSerializer.
     */
    @Test
    public void testCopyX509Certificate() throws Exception {
        X509Certificate copiedCert = X509CertificateSerializer.copyX509Certificate(x509certificate);
        File originFolder = new File(tempFolder, "origin");
        assertTrue(originFolder.mkdir());
        File copiedFolder = new File(tempFolder, "copy");
        assertTrue(copiedFolder.mkdir());
        x509certificate.writeCertificate(originFolder.getAbsolutePath(), "origin");
        copiedCert.writeCertificate(copiedFolder.getAbsolutePath(), "copy");
        File origin = Objects.requireNonNull(originFolder.listFiles())[0];
        File copy = Objects.requireNonNull(copiedFolder.listFiles())[0];

        assertArrayEquals(Files.readAllBytes(origin.toPath()), Files.readAllBytes(copy.toPath()));
    }

}
