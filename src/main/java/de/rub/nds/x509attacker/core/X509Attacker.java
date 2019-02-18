package de.rub.nds.x509attacker.core;

import de.rub.nds.x509attacker.core.keyfilemanager.KeyFileContent;
import de.rub.nds.x509attacker.core.keyfilemanager.KeyFileManager;
import de.rub.nds.x509attacker.core.keyfilemanager.KeyFileManagerException;
import de.rub.nds.x509attacker.core.xmlparser.X509AttackerXmlParser;
import de.rub.nds.x509attacker.core.xmlparser.X509AttackerXmlParserException;
import de.rub.nds.x509attacker.x509.model.meta.X509CertificateList;

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

    public void run(final String inputXml, final KeyFileContent[] keyFileContents, final String certficateOutputPath) throws X509AttackerException {
        try {
            KeyFileManager keyFileManager = new KeyFileManager(keyFileContents);
            X509AttackerXmlParser xmlParser = new X509AttackerXmlParser(inputXml);
            X509CertificateList certificateList = xmlParser.getX509CertificateList();
            byte[] tbsCertContent = certificateList.getCertificate(0).getTbsCertificate().encode();
            int i = 0;
        } catch (KeyFileManagerException e) {
            throw new X509AttackerException(e);
        } catch (X509AttackerXmlParserException e) {
            throw new X509AttackerException(e);
        }
    }
}
