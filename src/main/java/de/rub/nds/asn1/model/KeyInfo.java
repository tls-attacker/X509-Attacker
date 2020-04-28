package de.rub.nds.asn1.model;

import de.rub.nds.signatureengine.SignatureEngine;
import de.rub.nds.signatureengine.keyparsers.DefaultKeyParser;
import de.rub.nds.signatureengine.keyparsers.KeyParserException;
import de.rub.nds.signatureengine.keyparsers.KeyType;
import de.rub.nds.signatureengine.keyparsers.PemUtil;
import de.rub.nds.x509attacker.filesystem.BinaryFileReader;
import de.rub.nds.x509attacker.keyfilemanager.KeyFileManagerException;
import java.io.File;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
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
        } catch(IOException e) {
            throw new IOException(e);
        }
    }

    public KeyType getKeyType() {
        return keyType;
    }

    public void setKeyType(KeyType keyType) {
        this.keyType = keyType;
    }
    
    
        
}
