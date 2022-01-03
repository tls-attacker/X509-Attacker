/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.asn1.model;

import de.rub.nds.signatureengine.keyparsers.KeyType;
import de.rub.nds.signatureengine.keyparsers.PemUtil;
import de.rub.nds.x509attacker.filesystem.BinaryFileReader;
import java.io.File;
import java.io.IOException;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import org.apache.logging.log4j.LogManager;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyInfo extends Asn1PseudoType {

    private static final org.apache.logging.log4j.Logger LOGGER = LogManager.getLogger(KeyInfo.class);

    @XmlElement(name = "keyFile")
    private String keyFileName = "";

    @XmlElement(name = "keyFile_File")
    private File keyFile;

    private KeyType keyType;

    private byte[] keyBytes = null;

    @XmlElement(name = "pubKeyFile")
    private String pubKeyFile = "";

    public KeyInfo() {

    }

    public File getKeyFile() {
        return keyFile;
    }

    public void setKeyFile(File keyFile) throws IOException {
        this.keyFile = keyFile;
        this.keyFileName = keyFile.getName();
        this.keyBytes = readKeyFile(keyFile);
        this.keyType = PemUtil.getKeyType(keyFile);
    }

    public String getKeyFileName() {
        return keyFileName;
    }

    public void setKeyFileName(String keyFileName) {
        this.keyFileName = keyFileName;
    }

    public byte[] getKeyBytes() {
        return keyBytes;
    }

    public void setKeyBytes(byte[] keyBytes) {
        this.keyBytes = keyBytes;
    }

    private byte[] readKeyFile(File keyFile) throws IOException {
        try {
            BinaryFileReader binaryFileReader = new BinaryFileReader(keyFile.getAbsolutePath());
            byte[] keyFileContent = binaryFileReader.read();
            return keyFileContent;
        } catch (IOException e) {
            throw new IOException(e);
        }
    }

    public KeyType getKeyType() {
        return keyType;
    }

    public void setKeyType(KeyType keyType) {
        this.keyType = keyType;
    }

    public String getPubKeyFile() {
        // Fallback to keyFile if pubKeyFile is empty.
        if (pubKeyFile.isEmpty()) {
            return keyFile.getAbsolutePath();
        }
        return pubKeyFile;
    }

    public void setPubKeyFile(String pubKeyFile) {
        this.pubKeyFile = pubKeyFile;
    }

}
