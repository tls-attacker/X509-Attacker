package de.rub.nds.x509attacker.filesystem;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class BinaryFileWriter {

    private final String directory;

    private final String filename;

    public BinaryFileWriter(final String filename) {
        this("", filename);
    }

    public BinaryFileWriter(final String directory, final String filename) {
        this.directory = directory;
        this.filename = filename;
    }

    public void write(byte[] content) throws IOException {
        if(content != null) {
            this.write(content, 0, content.length);
        }
    }

    public void write(byte[] content, int offset, int length) throws IOException {
        File file = new File(this.directory, this.filename);
        FileOutputStream fileOutputStream = new FileOutputStream(file);
        fileOutputStream.write(content, offset, length);
        fileOutputStream.flush();
        fileOutputStream.close();
    }
}
