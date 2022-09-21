/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.x509;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.x509attacker.helper.X509Factory;
import de.rub.nds.x509attacker.constants.X509CertChainOutFormat;
import de.rub.nds.x509attacker.registry.Registry;
import de.rub.nds.x509attacker.repairchain.RepairChainConfig;
import java.io.File;
import java.io.IOException;
import java.util.Objects;

import jakarta.xml.bind.JAXBException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.xml.stream.XMLStreamException;

public class X509CertificateChainTest {

    @TempDir
    public File tempFolder;

    private static X509CertificateChain x509certificateChain;
    private static final int numberOfCerts = 4;

    @BeforeAll
    public static void setUpClass() throws IOException, JAXBException, XMLStreamException {
        Registry.getInstance();

        x509certificateChain = X509Factory.generateRandomX509CertificateChain(new File("resources/x509Certificates"),
            new File("resources/keys"), numberOfCerts,
            RepairChainConfig.createRepairAllAndSignConfig("resources/keys"));
    }

    /**
     * Test of writeCertificateChainToFile method, of class X509CertificateChain.
     */
    @Test
    public void testWriteCertificateChain() {
        System.out.println("writeCertificateChain");
        System.out.println("Test TempFolder path: " + tempFolder.getAbsolutePath());

        String directoryPath = tempFolder.getAbsolutePath();
        x509certificateChain.writeCertificateChainToFile(directoryPath, X509CertChainOutFormat.ROOT_CERT);
        assertEquals(1, Objects.requireNonNull(tempFolder.list()).length);
        clearFolder(tempFolder);

        x509certificateChain.writeCertificateChainToFile(directoryPath, X509CertChainOutFormat.LEAF_CERT);
        assertEquals(1, Objects.requireNonNull(tempFolder.list()).length);
        clearFolder(tempFolder);

        x509certificateChain.writeCertificateChainToFile(directoryPath, X509CertChainOutFormat.INTER_CERTS);
        assertTrue(Objects.requireNonNull(tempFolder.list()).length >= 1);
        clearFolder(tempFolder);

        x509certificateChain.writeCertificateChainToFile(directoryPath, X509CertChainOutFormat.INTER_CERTS_COMBINED);
        assertEquals(1, Objects.requireNonNull(tempFolder.list()).length);
        clearFolder(tempFolder);

        x509certificateChain.writeCertificateChainToFile(directoryPath,
            X509CertChainOutFormat.INTER_LEAF_CERTS_COMBINED);
        assertEquals(1, Objects.requireNonNull(tempFolder.list()).length);
        clearFolder(tempFolder);

        x509certificateChain.writeCertificateChainToFile(directoryPath,
            X509CertChainOutFormat.ROOT_INTER_LEAF_CERTS_COMBINED);
        assertEquals(1, Objects.requireNonNull(tempFolder.list()).length);
        clearFolder(tempFolder);

        x509certificateChain.writeCertificateChainToFile(directoryPath,
            X509CertChainOutFormat.CHAIN_ALL_IND_ROOT_TO_LEAF);
        assertEquals(numberOfCerts, Objects.requireNonNull(tempFolder.list()).length);
        clearFolder(tempFolder);

        x509certificateChain.writeCertificateChainToFile(directoryPath, X509CertChainOutFormat.CHAIN_COMBINED);
        assertEquals(1, Objects.requireNonNull(tempFolder.list()).length);
        clearFolder(tempFolder);

        x509certificateChain.writeCertificateChainToFile(directoryPath, X509CertChainOutFormat.CHAIN_GROUPED3);
        assertEquals(3, Objects.requireNonNull(tempFolder.list()).length);
        clearFolder(tempFolder);

        x509certificateChain.writeCertificateChainToFile(directoryPath, X509CertChainOutFormat.CHAIN_GROUPED2);
        assertEquals(2, Objects.requireNonNull(tempFolder.list()).length);
        clearFolder(tempFolder);

    }

    private void clearFolder(File folder) {
        for (File file : Objects.requireNonNull(folder.listFiles())) {
            if (!file.isDirectory()) {
                assertTrue(file.delete());
            }
        }
    }
}
