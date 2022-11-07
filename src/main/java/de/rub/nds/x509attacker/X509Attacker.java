/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.encoder.Asn1EncoderForX509;
import de.rub.nds.asn1.parser.Asn1Parser;
import de.rub.nds.asn1.parser.ParserException;
import de.rub.nds.asn1.translator.*;
import de.rub.nds.asn1.util.AttributeParser;
import de.rub.nds.asn1tool.filesystem.TextFileReader;
import de.rub.nds.asn1tool.xmlparser.Asn1XmlContent;
import de.rub.nds.asn1tool.xmlparser.XmlConverter;
import de.rub.nds.asn1tool.xmlparser.XmlParser;
import de.rub.nds.x509attacker.filesystem.CertificateFileReader;
import de.rub.nds.x509attacker.filesystem.CertificateFileWriter;
import de.rub.nds.x509attacker.keyfilemanager.KeyFileManager;
import de.rub.nds.x509attacker.keyfilemanager.KeyFileManagerException;
import de.rub.nds.x509attacker.linker.Linker;
import de.rub.nds.x509attacker.registry.Registry;
import de.rub.nds.x509attacker.x509.createIdentifierMap;
import de.rub.nds.x509attacker.xmlsignatureengine.XmlSignatureEngine;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class X509Attacker {

    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) {
        // Parse program arguments
        if (args.length > 0) {
            switch (args[0]) {
                case "xml2cert": {
                    if (args.length == 4) {
                        xmlToCertificate(args[1], args[2], args[3]);
                    } else {
                        printHelp();
                    }
                    break;
                }

                case "cert2xml": {
                    if (args.length == 3) {
                        certificateToXml(args[1], args[2]);
                    } else {
                        printHelp();
                    }
                    break;
                }

                default: {
                    printHelp();
                    break;
                }
            }
        } else {
            printHelp();
        }
    }

    private static void printHelp() {
        LOGGER
            .info("Usage: x509attacker xml2cert [input xml file] [key file directory] [output certificate directory]");
        LOGGER.info("   or: x509attacker cert2xml [input certificate file] [output xml file]");
        LOGGER.info("");
        LOGGER.info("[input xml file]                the file name of the xml input file");
        LOGGER.info("[key file directory]            the directory where key files are stored");
        LOGGER.info("[output certificate directory]  the directory where output certificates are created");
        LOGGER.info("");
        LOGGER.info("[input certificate file]        the input certificate file");
        LOGGER.info("[output xml file]               the output xml file");
    }

    public static void xmlToCertificate(final String xmlFile, final String keyDirectory,
        final String certificateOutputDirectory) {
        try {
            Registry.getInstance();

            // Read XML file
            TextFileReader textFileReader = new TextFileReader(xmlFile);
            String xmlString = textFileReader.read();

            // Parse XML
            XmlParser xmlParser = new XmlParser(xmlString);
            Asn1XmlContent asn1XmlContent = xmlParser.getAsn1XmlContent();
            Map<String, Asn1Encodable> identifierMap = xmlParser.getIdentifierMap();

            // Create links
            Linker linker = new Linker(identifierMap);

            // Load key files
            KeyFileManager keyFileManager = KeyFileManager.getReference();
            keyFileManager.init(keyDirectory);

            // Encode XML for certificate
            List<Asn1Encodable> certificates = asn1XmlContent.getAsn1Encodables();
            byte[][] encodedCertificates = new byte[certificates.size()][];
            for (int i = 0; i < certificates.size(); i++) {
                encodedCertificates[i] = Asn1EncoderForX509.encodeForCertificate(linker, certificates.get(i));
            }

            // Write certificate files
            writeCertificates(certificateOutputDirectory, certificates, encodedCertificates);

            LOGGER.info("Done.");
        } catch (KeyFileManagerException | IOException e) {
            LOGGER.error(e);
        }
    }

    public static void certificateToXml(final String certificateFile, final String xmlFile) {
        try {
            Registry.getInstance();

            // Read certificate file
            CertificateFileReader certificateFileReader = new CertificateFileReader(certificateFile);
            byte[] certificateContent = certificateFileReader.readBytes();

            // Parse certificate
            Asn1Parser asn1Parser = new Asn1Parser(certificateContent, false);
            List<Asn1Encodable> asn1Encodables = asn1Parser.parse(ParseNativeTypesContext.NAME);
            Asn1XmlContent asn1XmlContent = new Asn1XmlContent();
            asn1XmlContent.setAsn1Encodables(asn1Encodables);

            // Write XML file
            XmlConverter xmlConverter = new XmlConverter(asn1XmlContent, new File(xmlFile));

            LOGGER.info("Done.");
        } catch (IOException | ParserException e) {
            LOGGER.error(e);
        }
    }

    public static void loadCertificate(final String certificateFile, final String xmlFile) throws ParserException {
        try {
            Registry.getInstance();

            // Read certificate file
            CertificateFileReader certificateFileReader = new CertificateFileReader(certificateFile);
            byte[] certificateContent = certificateFileReader.readBytes();

            // Parse certificate
            Asn1Parser asn1Parser = new Asn1Parser(certificateContent, false);

            // Certificate Content
            List<Asn1Encodable> asn1Encodables = asn1Parser.parse(CertificateOuterContext.NAME);

            // Extension Content
            // List<Asn1Encodable> asn1Encodables = asn1Parser.parse(TestExtensionsContext.NAME);
            createIdentifierMap createMap = new createIdentifierMap();
            Map<String, Asn1Encodable> identifierMap = createMap.createMap(asn1Encodables);

            /*
             * certificate.setAsn1Encodable(asn1Encodables); //Create IdentifierMap createIdentifierMap createMap = new
             * createIdentifierMap(); //TODO: bei gleicher Identifier bezeichnung ein Index einfügen Map<String,
             * Asn1Encodable> identifierMap = createMap.createMap(certificate.getAsn1Encodable());
             * certificate.setIdentifierMap(identifierMap);
             */
            Asn1XmlContent asn1XmlContent = new Asn1XmlContent();
            asn1XmlContent.setAsn1Encodables(asn1Encodables);

            // Write XML file
            XmlConverter xmlConverter = new XmlConverter(asn1XmlContent, new File(xmlFile));

            LOGGER.info("Done.");
        } catch (IOException | ParserException e) {
            throw new ParserException(e);
        }
    }

    private static void writeCertificates(final String certificateOutputDirectory,
        final List<Asn1Encodable> certificates, final byte[][] encodedCertificates) throws IOException {
        CertificateFileWriter certificateChainFileWriter =
            new CertificateFileWriter(certificateOutputDirectory, "certificate_chain.pem");
        for (int i = 0; i < certificates.size(); i++) {
            Asn1Encodable certificate = certificates.get(i);
            if (certificate.getType().equalsIgnoreCase("Certificate") == false) {
                continue;
            }
            // Append certificate to certificate chain file
            if (AttributeParser.parseBooleanAttributeOrDefault(certificate, X509Attributes.ATTACH_TO_CERTIFICATE_LIST,
                false)) {
                certificateChainFileWriter.writeCertificate(encodedCertificates[i]);
            }
            // Write certificate in its own file
            writeSingleCertificate(certificateOutputDirectory, certificate, encodedCertificates[i]);
        }
        certificateChainFileWriter.close();
    }

    private static void writeSingleCertificate(final String certificateOutputDirectory, final Asn1Encodable certificate,
        final byte[] encodedCertificate) throws IOException {
        String certificateFileName = certificate.getIdentifier() + ".pem";
        CertificateFileWriter certificateFileWriter =
            new CertificateFileWriter(certificateOutputDirectory, certificateFileName);
        certificateFileWriter.writeCertificate(encodedCertificate);
        certificateFileWriter.close();
    }
}
