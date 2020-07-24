package de.rub.nds.x509attacker.x509;


import de.rub.nds.x509attacker.helper.X509Factory;
import de.rub.nds.x509attacker.constants.X509CertChainOutFormat;
import de.rub.nds.x509attacker.exceptions.RepairChainException;
import de.rub.nds.x509attacker.repairchain.RepairChainConfig;
import java.io.File;
import java.io.IOException;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;


public class X509CertificateChainTest {
    
    
    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();
    
    private static X509CertificateChain x509certificateChain;
    private static int numberOfCerts = 4;
    
    @BeforeClass
    public static void setUpClass() throws IOException, JAXBException, XMLStreamException{
        x509certificateChain = X509Factory.generateRandomX509CertificateChain(new File("resources/x509Certificates"),new File("resources/keys"),numberOfCerts, RepairChainConfig.createRepairAllAndSignConfig("resources/keys"));
            
    }    

    /**
     * Test of signAllCertificates method, of class X509CertificateChain.
     */
    @Test
    public void testSignAllCertificates() {
        System.out.println("signAllCertificates");
        X509CertificateChain instance = new X509CertificateChain();
        instance.signAllCertificates();
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of repairChain method, of class X509CertificateChain.
     */
    @Test
    public void testRepairChain() throws RepairChainException{
        System.out.println("repairChain");
        X509CertificateChain instance = new X509CertificateChain();
        instance.repairAndSignChain();
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of writeCertificateChainToFile method, of class X509CertificateChain.
     */
    @Test
    public void testWriteCertificateChain() {
        System.out.println("writeCertificateChain");
        System.out.println("Test TempFolder path: " + tempFolder.getRoot().getPath());
        
        String directoryPath = tempFolder.getRoot().getPath();
        x509certificateChain.writeCertificateChainToFile(directoryPath, X509CertChainOutFormat.ROOT_CERT);
        assertTrue(tempFolder.getRoot().list().length == 1);
        clearFolder(tempFolder.getRoot());
        
        x509certificateChain.writeCertificateChainToFile(directoryPath, X509CertChainOutFormat.LEAF_CERT);
        assertTrue(tempFolder.getRoot().list().length == 1);
        clearFolder(tempFolder.getRoot());
        
        x509certificateChain.writeCertificateChainToFile(directoryPath, X509CertChainOutFormat.INTER_CERTS);
        assertTrue(tempFolder.getRoot().list().length >= 1);
        clearFolder(tempFolder.getRoot());
        
        x509certificateChain.writeCertificateChainToFile(directoryPath, X509CertChainOutFormat.INTER_CERTS_COMBINED);
        assertTrue(tempFolder.getRoot().list().length == 1);
        clearFolder(tempFolder.getRoot());
        
        x509certificateChain.writeCertificateChainToFile(directoryPath, X509CertChainOutFormat.INTER_LEAF_CERTS_COMBINED);
        assertTrue(tempFolder.getRoot().list().length == 1);
        clearFolder(tempFolder.getRoot());
        
        x509certificateChain.writeCertificateChainToFile(directoryPath, X509CertChainOutFormat.ROOT_INTER_LEAF_CERTS_COMBINED);
        assertTrue(tempFolder.getRoot().list().length == 1);
        clearFolder(tempFolder.getRoot());
        
        x509certificateChain.writeCertificateChainToFile(directoryPath, X509CertChainOutFormat.CHAIN_ALL_IND_ROOT_TO_LEAF);
        assertTrue(tempFolder.getRoot().list().length == numberOfCerts);
        clearFolder(tempFolder.getRoot());
        
        x509certificateChain.writeCertificateChainToFile(directoryPath, X509CertChainOutFormat.CHAIN_COMBINED);
        assertTrue(tempFolder.getRoot().list().length == 1);
        clearFolder(tempFolder.getRoot());
        
        x509certificateChain.writeCertificateChainToFile(directoryPath, X509CertChainOutFormat.CHAIN_GROUPED3);
        assertTrue(tempFolder.getRoot().list().length == 3);
        clearFolder(tempFolder.getRoot());
        
        x509certificateChain.writeCertificateChainToFile(directoryPath, X509CertChainOutFormat.CHAIN_GROUPED2);
        assertTrue(tempFolder.getRoot().list().length == 2);
        clearFolder(tempFolder.getRoot());
        
    }
    
    private void clearFolder(File folder)
    {
        for(File file: folder.listFiles()) {
            if (!file.isDirectory()) {
                file.delete();
            }
        }
    }
}
