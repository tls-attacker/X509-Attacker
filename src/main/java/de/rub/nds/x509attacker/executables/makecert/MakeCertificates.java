package de.rub.nds.x509attacker.executables.makecert;

import de.rub.nds.x509.linker.Linker;
import de.rub.nds.x509.linker.LinkerException;
import de.rub.nds.x509.model.X509CertificateList;
import de.rub.nds.x509attacker.certificatesigner.CertificateSigner;
import de.rub.nds.x509attacker.certificatesigner.CertificateSignerException;
import de.rub.nds.x509attacker.filesystem.CertificateFileWriter;
import de.rub.nds.x509attacker.filesystem.TextFileReader;
import de.rub.nds.x509attacker.keyfilemanager.KeyFileManager;
import de.rub.nds.x509attacker.keyfilemanager.KeyFileManagerException;
import de.rub.nds.x509attacker.xmlparser.X509AttackerXmlParser;
import de.rub.nds.x509attacker.xmlparser.X509AttackerXmlParserException;
import org.apache.commons.cli.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.Security;

public class MakeCertificates {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        Option input = new Option("i", "input", true, "Input XML file");
        input.setRequired(true);

        Option certificateOutputPath = new Option("certoutdir", "certificateoutputdirectory", true, "Certificate output directory");
        certificateOutputPath.setRequired(true);

        Option keyDir = new Option("keydir", "keydirectory", true, "Key file directory");
        keyDir.setRequired(true);


        Options options = new Options();
        options.addOption(input);
        options.addOption(certificateOutputPath);
        options.addOption(keyDir);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        try {
            cmd = parser.parse(options, args);
            run(cmd.getOptionValue("keydir"), cmd.getOptionValue("certoutdir"), cmd.getOptionValue("input"));
        } catch (ParseException e) {
            System.out.println(e.getMessage() + "\r\n");
            formatter.printHelp("utility-name", options);
        }
    }

    public static void run(final String keyFileDirectory, final String certificateOutputDirectory, final String xmlFilePath) {
        try {
            KeyFileManager.getReference().init(keyFileDirectory);
            TextFileReader xmlFileReader = new TextFileReader(xmlFilePath);
            String xml = xmlFileReader.read();
            X509AttackerXmlParser xmlParser = new X509AttackerXmlParser(xml);
            X509CertificateList x509CertificateList = xmlParser.getX509CertificateList();
            Linker linker = new Linker(x509CertificateList);
            CertificateSigner certificateSigner = new CertificateSigner(x509CertificateList);
            certificateSigner.signCertificates();
            CertificateFileWriter certificateFileWriter = new CertificateFileWriter(certificateOutputDirectory);
            certificateFileWriter.writeCertificates(x509CertificateList);
        } catch (KeyFileManagerException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch(X509AttackerXmlParserException e) {
            e.printStackTrace();
        } catch(LinkerException e) {
            e.printStackTrace();
        } catch(CertificateSignerException e) {
            e.printStackTrace();
        }
    }
}
