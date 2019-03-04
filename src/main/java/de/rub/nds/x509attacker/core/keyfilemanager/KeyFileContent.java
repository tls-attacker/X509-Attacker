package de.rub.nds.x509attacker.core.keyfilemanager;

public class KeyFileContent {

    private static int idCounter = 1;

    public final int id;

    public final byte[] keyFileContent;

    public KeyFileContent(byte[] keyFileContent) {
        this.id = getNextId();
        this.keyFileContent = keyFileContent;
    }

    private static int getNextId() {
        int nextId = idCounter;
        idCounter++;
        return nextId;
    }
}
