/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.helper;

import de.rub.nds.x509attacker.repairchain.RepairChainConfig;
import de.rub.nds.asn1.parser.ParserException;
import de.rub.nds.asn1.parser.X509Parser;
import de.rub.nds.modifiablevariable.util.RandomHelper;
import de.rub.nds.signatureengine.keyparsers.KeyType;
import de.rub.nds.x509attacker.helper.KeyFactory;
import de.rub.nds.x509attacker.x509.X509Certificate;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import java.io.File;
import java.io.IOException;
import java.util.Random;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author josh Helper functions to create X509Certificate or X509CertificateChains from a folder of valid X.509
 *         certificates
 */
public class X509Factory {

    static final Logger LOGGER = LogManager.getLogger(X509Factory.class);

    public static X509Certificate getRandomX509CertificateFromFolder(File certificateFolder)
        throws IOException, JAXBException, XMLStreamException {
        return getRandomX509CertificateFromFolder(certificateFolder, null, null);
    }

    public static X509Certificate getRandomX509CertificateFromFolder(File certificateFolder, File keyFolder)
        throws IOException, JAXBException, XMLStreamException {
        return getRandomX509CertificateFromFolder(certificateFolder, keyFolder, null);
    }

    public static X509Certificate getRandomX509CertificateFromFolder(File certificateFolder, File keyFolder,
        KeyType keyType) throws IOException, JAXBException, XMLStreamException {
        X509Certificate cert = null;
        int tries = 0;

        if (certificateFolder.exists() && certificateFolder.isDirectory()) {
            File chosenFile = null;
            do {
                File[] files = certificateFolder.listFiles();
                Random r = RandomHelper.getRandom();
                chosenFile = files[r.nextInt(files.length)];

                try {

                    X509Parser x509Parser = new X509Parser(chosenFile);
                    cert = x509Parser.parse();

                    if (keyFolder != null) {
                        File keyFile = KeyFactory.getRandomKeyFileFromFolder(keyFolder, keyType);
                        cert.setKeyFile(keyFile);
                    }

                } catch (IOException | ParserException E) {
                    LOGGER.warn("getRandomX509CertificateFromFolder(): Could not parse Random X509Certificate: "
                        + chosenFile.getAbsolutePath() + " Exception: " + E);
                }
                tries++;

            } while (cert == null && tries < 10);

        } else {

            throw new IOException("Cannot generate a new X509Certificate from " + certificateFolder.getAbsolutePath()
                + "(not exists or no directory)");
        }

        return cert;
    }

    public static X509CertificateChain generateRandomX509CertificateChain(File certificateFolder, File keyFolder,
        int numberOfCerts, RepairChainConfig repairConfig) throws IOException, JAXBException, XMLStreamException {
        LOGGER.trace("Generation of random certificate chain started (with: " + numberOfCerts + " certs)");
        X509CertificateChain generatedCertChain = new X509CertificateChain();

        for (int i = 0; i < numberOfCerts; i++) {
            generatedCertChain.addCertificate(getRandomX509CertificateFromFolder(certificateFolder, keyFolder));
        }

        generatedCertChain.repairChain(repairConfig);

        if (generatedCertChain.getCertificateChain().isEmpty()) {
            throw new IOException("Generation of random certificate chain failed: generatedChain is empty");
        }
        LOGGER.trace("Generation of random certificate chain finished");
        return generatedCertChain;
    }
}
