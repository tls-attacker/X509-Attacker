/*
 * TLS-Attacker - A Modular Penetration Testing Framework for TLS
 *
 * Copyright 2014-2020 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package de.rub.nds.x509attacker.keyfilemanager;

import de.rub.nds.x509attacker.filesystem.BinaryFileReader;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class KeyFileManager {

    private static KeyFileManager reference = null;

    private File keyFileDirectory = new File("");

    private final Map<String, byte[]> keyFileMap = new HashMap<>();

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

    public void init(String keyFileDirectory) throws KeyFileManagerException {
        if (this.keyFileMap.isEmpty()) {
            this.keyFileDirectory = new File(keyFileDirectory);
            this.readAllKeyFiles();
        }
    }

    private void readAllKeyFiles() throws KeyFileManagerException {
        File[] keyFiles = this.keyFileDirectory.listFiles();
        if (keyFiles != null) {
            for (File keyFile : keyFiles) {
                this.readKeyFile(keyFile);
            }
        }
    }

    private void readKeyFile(File keyFile) throws KeyFileManagerException {
        try {
            BinaryFileReader binaryFileReader = new BinaryFileReader(keyFile.getAbsolutePath());
            byte[] keyFileContent = binaryFileReader.read();
            this.addKeyFile(keyFile.getName(), keyFileContent);
        } catch (IOException e) {
            throw new KeyFileManagerException(e);
        }
    }

    private void addKeyFile(String filename, byte[] content) throws KeyFileManagerException {
        String sanitizedFilename = this.sanitizeKeyFileName(filename);
        if (!this.keyFileMap.containsKey(sanitizedFilename)) {
            this.keyFileMap.put(sanitizedFilename, content);
        }
    }

    private String sanitizeKeyFileName(String filename) throws KeyFileManagerException {
        return filename.trim();
    }

    public byte[] getKeyFileContent(String filename) throws KeyFileManagerException {
        String sanitizedFilename = this.sanitizeKeyFileName(filename);
        if (this.keyFileMap.containsKey(sanitizedFilename)) {
            return this.keyFileMap.get(sanitizedFilename);
        } else {
            throw new KeyFileManagerException("Key file " + filename + " is not available!");
        }
    }
}
