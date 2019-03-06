package de.rub.nds.x509attacker.core;

import de.rub.nds.x509attacker.core.certificatelinker.CertificateLinker;
import de.rub.nds.x509attacker.core.certificatelinker.CertificateLinkerException;
import de.rub.nds.x509attacker.core.certificatesigner.CertificateSigner;
import de.rub.nds.x509attacker.core.certificatesigner.CertificateSignerException;
import de.rub.nds.x509attacker.core.keyfilemanager.KeyFileManager;
import de.rub.nds.x509attacker.core.keyfilemanager.KeyFileManagerException;
import de.rub.nds.x509attacker.core.xmlparser.X509AttackerXmlParser;
import de.rub.nds.x509attacker.core.xmlparser.X509AttackerXmlParserException;
import de.rub.nds.x509attacker.x509.model.nonasn1.X509CertificateList;

public class X509Attacker {

    private static X509Attacker instance = null;

    private X509Attacker() {

    }

    public static X509Attacker getInstance() {
        if (instance == null) {
            synchronized (X509Attacker.class) {
                if (instance == null) {
                    instance = new X509Attacker();
                }
            }
        }
        return instance;
    }

    public void run(final String inputXml, final String certficateOutputPath, final String keyFileOutputPath) throws X509AttackerException {
        try {
            // Parse XML
            X509AttackerXmlParser xmlParser = new X509AttackerXmlParser(inputXml);
            X509CertificateList certificateList = xmlParser.getX509CertificateList();

            // Load keys
            KeyFileManager keyFileManager = KeyFileManager.getReference();
            keyFileManager.loadAllKeyFiles(certificateList);

            // Todo: Generate missing key files?

            // Link certificate fields
            CertificateLinker certificateLinker = new CertificateLinker(certificateList);
            certificateLinker.updateReferencedFields();

            // Sign certificates
            CertificateSigner.signAllCertificates(certificateList);
            int i = 0;
        } catch (KeyFileManagerException e) {
            throw new X509AttackerException(e);
        } catch (X509AttackerXmlParserException e) {
            throw new X509AttackerException(e);
        } catch (CertificateLinkerException e) {
            throw new X509AttackerException(e);
        } catch (CertificateSignerException e) {
            throw new X509AttackerException(e);
        }
    }
}
