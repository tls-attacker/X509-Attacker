package de.rub.nds.x509attacker.core.keyfilemanager;

import de.rub.nds.x509attacker.x509.model.nonasn1.KeyInfo;
import de.rub.nds.x509attacker.x509.model.nonasn1.RealSignatureInfo;
import de.rub.nds.x509attacker.x509.model.nonasn1.X509CertificateList;
import de.rub.nds.x509attacker.x509.model.types.basiccertificate.X509Certificate;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class KeyFileManager {

    private static KeyFileManager reference = null;

    private final Map<Integer, KeyFileContent> keyFileMap = new HashMap<>();

    private KeyFileManager() {

    }

    public static KeyFileManager getReference() {
        if (reference == null) {
            synchronized (KeyFileManager.class) {
                if (reference == null) {
                    reference = new KeyFileManager();
                }
            }
        }
        return reference;
    }

    public void loadAllKeyFiles(X509CertificateList certificateList) throws KeyFileManagerException {
        this.loadAllCertificateKeyFiles(certificateList);
        this.loadAllKeyInfoKeyFiles(certificateList);
    }

    public void loadAllCertificateKeyFiles(X509CertificateList certificateList) throws KeyFileManagerException {
        for (X509Certificate certificate : certificateList.getCertificates()) {
            this.loadCertificateKeyFile(certificate);
        }
    }

    public void loadCertificateKeyFile(X509Certificate certificate) throws KeyFileManagerException {
        String keyFileName = certificate.getKeyFile();
        if (keyFileName != null && !keyFileName.trim().equals("")) {
            byte[] rawKeyFileContent = this.readFile(keyFileName);
            KeyFileContent keyFileContent = new KeyFileContent(rawKeyFileContent);
            this.addKeyFile(keyFileContent);
            certificate.setKeyFileId(keyFileContent.id);
        } else {
            throw new KeyFileManagerException("No key file specified for a certificate!");
        }
    }

    public void loadAllKeyInfoKeyFiles(X509CertificateList certificateList) throws KeyFileManagerException {
        for (X509Certificate certificate : certificateList.getCertificates()) {
            RealSignatureInfo realSignatureInfo = certificate.getRealSignatureInfo();
            if (realSignatureInfo != null) {
                KeyInfo keyInfo = realSignatureInfo.getKeyInfo();
                if (keyInfo != null) {
                    this.loadKeyInfoKeyFile(keyInfo);
                }
            }
        }
    }

    public void loadKeyInfoKeyFile(KeyInfo keyInfo) throws KeyFileManagerException {
        String keyFileName = keyInfo.getKeyFile();
        if (keyFileName != null && !keyFileName.trim().equals("")) {
            byte[] rawKeyFileContent = this.readFile(keyFileName);
            KeyFileContent keyFileContent = new KeyFileContent(rawKeyFileContent);
            this.addKeyFile(keyFileContent);
            keyInfo.setKeyFileId(keyFileContent.id);
        } else {
            throw new KeyFileManagerException("No key file specified for a KeyInfo!");
        }
    }

    private byte[] readFile(String fileName) throws KeyFileManagerException {
        byte[] content = null;
        try {
            File file = new File(fileName);
            FileInputStream fileInputStream = new FileInputStream(file);
            int bytesRead = 0;
            int totalBytesRead = 0;
            byte[] buffer = new byte[2048];
            content = new byte[(int) file.length()];
            while (bytesRead != -1) {
                bytesRead = fileInputStream.read(buffer);
                if (bytesRead != -1) {
                    System.arraycopy(buffer, 0, content, totalBytesRead, bytesRead);
                    totalBytesRead += bytesRead;
                }
            }
            return content;
        } catch (FileNotFoundException e) {
            throw new KeyFileManagerException(e);
        } catch (IOException e) {
            throw new KeyFileManagerException(e);
        }
    }

    public void addKeyFiles(KeyFileContent... keyFileContents) throws KeyFileManagerException {
        if (keyFileContents != null) {
            for (KeyFileContent keyFileContent : keyFileContents) {
                this.addKeyFile(keyFileContent);
            }
        }
    }

    public void addKeyFile(KeyFileContent keyFileContent) throws KeyFileManagerException {
        if (this.keyFileMap.containsKey(keyFileContent.id)) {
            throw new KeyFileManagerException("Unique key file identifier " + keyFileContent.id + " is already in use!");
        } else {
            this.keyFileMap.put(keyFileContent.id, keyFileContent);
        }
    }

    public KeyFileContent getKeyFile(int id) throws KeyFileManagerException {
        KeyFileContent keyFileContent = this.keyFileMap.get(id);
        if (keyFileContent == null) {
            throw new KeyFileManagerException("Key file with unique identifier " + id + " is not available!");
        }
        return keyFileContent;
    }
}
