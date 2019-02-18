package de.rub.nds.x509attacker.core.keyfilemanager;

import java.util.HashMap;
import java.util.Map;

public class KeyFileManager {

    private Map<Integer, KeyFileContent> keyFileMap;

    public KeyFileManager(KeyFileContent... keyFileContents) throws KeyFileManagerException {
        this.keyFileMap = new HashMap<>();
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
