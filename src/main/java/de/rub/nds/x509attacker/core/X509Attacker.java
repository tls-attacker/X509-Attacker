package de.rub.nds.x509attacker.core;

import de.rub.nds.x509attacker.core.certificatelinker.CertificateLinker;
import de.rub.nds.x509attacker.core.certificatelinker.CertificateLinkerException;
import de.rub.nds.x509attacker.core.keyfilemanager.KeyFileManager;
import de.rub.nds.x509attacker.core.keyfilemanager.KeyFileManagerException;
import de.rub.nds.x509attacker.core.xmlparser.X509AttackerXmlParser;
import de.rub.nds.x509attacker.core.xmlparser.X509AttackerXmlParserException;
import de.rub.nds.x509attacker.x509.encoder.EncodeMode;
import de.rub.nds.x509attacker.x509.encoder.X509Encoder;
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

            // Todo: Sign certificates
            // CertificateSigner.sign(certificateList);

            // Just some test stuff
            X509Encoder x509Encoder = X509Encoder.getReference();
            x509Encoder.setEncodeMode(EncodeMode.CERTIFICATE);
            byte[] encoded = x509Encoder.encode(certificateList.getCertificate(0));
            x509Encoder.setEncodeMode(EncodeMode.SIGNATURE);
            encoded = x509Encoder.encode(certificateList.getCertificate(0));
            int i = 0;
        } catch (KeyFileManagerException e) {
            throw new X509AttackerException(e);
        } catch (X509AttackerXmlParserException e) {
            throw new X509AttackerException(e);
        } catch (CertificateLinkerException e) {
            throw new X509AttackerException(e);
        }
    }
}
