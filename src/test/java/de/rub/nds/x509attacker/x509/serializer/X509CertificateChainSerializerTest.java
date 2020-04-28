
package de.rub.nds.x509attacker.x509.serializer;


import de.rub.nds.x509attacker.helper.X509Factory;
import de.rub.nds.x509attacker.constants.X509CertChainOutFormat;
import de.rub.nds.x509attacker.exceptions.RepairChainException;
import de.rub.nds.x509attacker.repairchain.RepairChainConfig;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.assertTrue;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

/**
 *
 * @author josh
 */
public class X509CertificateChainSerializerTest {

    private final Logger LOGGER = LogManager.getLogger();
    
    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();   
    
    
    private X509CertificateChain x509certificateChain;
   

    public X509CertificateChainSerializerTest() {
    }

    @Before
    public void setUp() throws IOException, JAXBException, XMLStreamException {
        x509certificateChain = X509Factory.generateRandomX509CertificateChain(new File("resources/x509Certificates"), new File("resources/keys"),3, RepairChainConfig.repairAllAndSignConfig);       
    }

    /**
     * Test of write method, of class X509CertificateChainSerializer.
     */
    @Test
    public void testWrite_File_X509CertificateChain() throws Exception {
        File file = tempFolder.newFile();
        X509CertificateChainSerializer.write(file, x509certificateChain);
    }

    /**
     * Test of write method, of class X509CertificateChainSerializer.
     */
    @Test
    public void testWrite_OutputStream_X509CertificateChain() throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        X509CertificateChainSerializer.write(outputStream, x509certificateChain);
        //LOGGER.info(new String(outputStream.toByteArray()));
    }

    /**
     * Test of read method, of class X509CertificateChainSerializer.
     */
    @Test
    public void testRead() throws Exception {
        File file = tempFolder.newFile();
        X509CertificateChainSerializer.write(file, x509certificateChain);
        X509CertificateChain chain = X509CertificateChainSerializer.read(new FileInputStream(file)); 
    }

    /**
     * Test of copyX509CertificateChain method, of class X509CertificateChainSerializer.
     */
    @Test
    public void testCopyX509CertificateChain() throws Exception {
        X509CertificateChain copiedChain = X509CertificateChainSerializer.copyX509CertificateChain(x509certificateChain);
        File originFolder = tempFolder.newFolder("origin");
        File copiedFolder = tempFolder.newFolder("copy");
        x509certificateChain.writeCertificateChainToFile(originFolder.getAbsolutePath(), X509CertChainOutFormat.CHAIN_COMBINED);
        copiedChain.writeCertificateChainToFile(copiedFolder.getAbsolutePath(), X509CertChainOutFormat.CHAIN_COMBINED);
        File origin = originFolder.listFiles()[0];
        File copy = copiedFolder.listFiles()[0];
        
        assertTrue(Arrays.equals(Files.readAllBytes(origin.toPath()), Files.readAllBytes(copy.toPath())));
    }

}

