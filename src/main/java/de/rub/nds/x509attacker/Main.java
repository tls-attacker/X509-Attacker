package de.rub.nds.x509attacker;

import de.rub.nds.x509attacker.core.X509Attacker;
import de.rub.nds.x509attacker.core.X509AttackerException;

import java.io.File;
import java.io.FileInputStream;

public class Main {
    public static void main(String[] args) {
        X509Attacker x509Attacker = X509Attacker.getInstance();
        try {
            File file = new File("C:\\Users\\Nils\\Documents\\Uni\\Masterarbeit\\X509-Attacker\\xmlcerts\\test-cert-1.xml");
            FileInputStream fileInputStream = new FileInputStream(file);
            int fileLength = (int) file.length();
            byte[] buffer = new byte[fileLength];
            fileInputStream.read(buffer);
            String fileContent = new String(buffer, 0, fileLength);

            x509Attacker.run(fileContent, "", "");
        } catch (X509AttackerException e) {
            System.err.println("Failed to execute X.509-Attacker for the given parameter set!");
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
