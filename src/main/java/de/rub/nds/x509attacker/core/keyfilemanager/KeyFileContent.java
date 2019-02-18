package de.rub.nds.x509attacker.core.keyfilemanager;

public class KeyFileContent {

    public final int id;

    public final byte[] keyFileContent;

    public KeyFileContent(int id, byte[] keyFileContent) {
        this.id = id;
        this.keyFileContent = keyFileContent;
    }
}
