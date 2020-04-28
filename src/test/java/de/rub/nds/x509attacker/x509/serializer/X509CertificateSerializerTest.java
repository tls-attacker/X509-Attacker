
package de.rub.nds.x509attacker.x509.serializer;


import de.rub.nds.x509attacker.helper.X509Factory;
import de.rub.nds.x509attacker.x509.X509Certificate;
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
public class X509CertificateSerializerTest {

    private final Logger LOGGER = LogManager.getLogger();
    
    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();   
    
    
    private X509Certificate x509certificate;
   

    public X509CertificateSerializerTest() {
    }

    @Before
    public void setUp() throws IOException, JAXBException, XMLStreamException {
        x509certificate = X509Factory.getRandomX509CertificateFromFolder(new File("resources/x509Certificates"), new File("resources/keys"));        
    }

    /**
     * Test of write method, of class X509CertificateSerializer.
     */
    @Test
    public void testWrite_File_X509Certificate() throws Exception {
        File file = tempFolder.newFile();
        X509CertificateSerializer.write(file, x509certificate);
    }

    /**
     * Test of write method, of class X509CertificateSerializer.
     */
    @Test
    public void testWrite_OutputStream_X509Certificate() throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        X509CertificateSerializer.write(outputStream, x509certificate);
        //LOGGER.info(new String(outputStream.toByteArray()));
    }

    /**
     * Test of read method, of class X509CertificateSerializer.
     */
    @Test
    public void testRead() throws Exception {
        File file = tempFolder.newFile();
        X509CertificateSerializer.write(file, x509certificate);
        X509Certificate cert = X509CertificateSerializer.read(new FileInputStream(file)); 
    }

    /**
     * Test of copyX509Certificate method, of class X509CertificateSerializer.
     */
    @Test
    public void testCopyX509Certificate() throws Exception {
        X509Certificate copiedCert = X509CertificateSerializer.copyX509Certificate(x509certificate);
        File originFolder = tempFolder.newFolder("origin");
        File copiedFolder = tempFolder.newFolder("copy");
        x509certificate.writeCertificate(originFolder.getAbsolutePath(), "origin");
        copiedCert.writeCertificate(copiedFolder.getAbsolutePath(), "copy");
        File origin = originFolder.listFiles()[0];
        File copy = copiedFolder.listFiles()[0];
        
        assertTrue(Arrays.equals(Files.readAllBytes(origin.toPath()), Files.readAllBytes(copy.toPath())));
    }

}

