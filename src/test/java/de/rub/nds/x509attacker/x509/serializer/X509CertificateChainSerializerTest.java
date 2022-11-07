/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509.serializer;

import de.rub.nds.x509attacker.constants.X509CertChainOutFormat;
import de.rub.nds.x509attacker.helper.X509Factory;
import de.rub.nds.x509attacker.registry.Registry;
import de.rub.nds.x509attacker.repairchain.RepairChainConfig;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import jakarta.xml.bind.JAXBException;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Objects;
import javax.xml.stream.XMLStreamException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class X509CertificateChainSerializerTest {

    private final Logger LOGGER = LogManager.getLogger();

    @TempDir
    public File tempFolder;

    private X509CertificateChain x509certificateChain;

    public X509CertificateChainSerializerTest() {
    }

    @BeforeEach
    public void setUp() throws IOException, JAXBException, XMLStreamException {
        Registry.getInstance();
        x509certificateChain = X509Factory.generateRandomX509CertificateChain(new File("resources/x509Certificates"),
            new File("resources/keys"), 3, RepairChainConfig.createRepairAllAndSignConfig("resources/keys"));
    }

    /**
     * Test of write method, of class X509CertificateChainSerializer.
     */
    @Test
    public void testWrite_File_X509CertificateChain() throws Exception {
        File file = new File(tempFolder, "x509CertificateChainWrite.tmp");
        assertTrue(file.createNewFile());
        X509CertificateChainSerializer.write(file, x509certificateChain);
    }

    /**
     * Test of write method, of class X509CertificateChainSerializer.
     */
    @Test
    public void testWrite_OutputStream_X509CertificateChain() throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        X509CertificateChainSerializer.write(outputStream, x509certificateChain);
        // LOGGER.info(new String(outputStream.toByteArray()));
    }

    /**
     * Test of read method, of class X509CertificateChainSerializer.
     */
    @Test
    public void testRead() throws Exception {
        File file = new File(tempFolder, "x509CertificateChainRead.tmp");
        assertTrue(file.createNewFile());
        X509CertificateChainSerializer.write(file, x509certificateChain);
        X509CertificateChain chain = X509CertificateChainSerializer.read(new FileInputStream(file));
    }

    /**
     * Test of copyX509CertificateChain method, of class X509CertificateChainSerializer.
     */
    @Test
    public void testCopyX509CertificateChain() throws Exception {
        X509CertificateChain copiedChain =
            X509CertificateChainSerializer.copyX509CertificateChain(x509certificateChain);
        File originFolder = new File(tempFolder, "origin");
        assertTrue(originFolder.mkdir());
        File copiedFolder = new File(tempFolder, "copy");
        assertTrue(copiedFolder.mkdir());
        x509certificateChain.writeCertificateChainToFile(originFolder.getAbsolutePath(),
            X509CertChainOutFormat.CHAIN_COMBINED);
        copiedChain.writeCertificateChainToFile(copiedFolder.getAbsolutePath(), X509CertChainOutFormat.CHAIN_COMBINED);
        File origin = Objects.requireNonNull(originFolder.listFiles())[0];
        File copy = Objects.requireNonNull(copiedFolder.listFiles())[0];

        assertArrayEquals(Files.readAllBytes(origin.toPath()), Files.readAllBytes(copy.toPath()));
    }

}
