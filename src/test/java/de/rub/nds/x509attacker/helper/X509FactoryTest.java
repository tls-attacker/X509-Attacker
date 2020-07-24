
package de.rub.nds.x509attacker.helper;

import de.rub.nds.x509attacker.helper.X509Factory;
import de.rub.nds.signatureengine.keyparsers.KeyType;
import de.rub.nds.x509attacker.helper.KeyFactory;
import de.rub.nds.x509attacker.x509.X509Certificate;
import java.io.File;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author josh
 */
public class X509FactoryTest {
    
    
    private File keyFolder;
    private File certificateFolder;
    
    public X509FactoryTest() {
    }
   
    @Before
    public void setUp() throws Exception {
        keyFolder = new File("resources/keys");
        certificateFolder = new File("resources/x509Certificates");
    }

    /**
     * Test of getRandomX509CertificateFromFolder method, of class X509Factory.
     */
    @Test
    public void testGetRandomX509CertificateFromFolder_File() throws Exception {        
        
        X509Certificate result = X509Factory.getRandomX509CertificateFromFolder(certificateFolder);
        assertNotNull(result);
    }
    
    /**
     * Test of getRandomX509CertificateFromFolder method, of class X509Factory.
     */
    @Test
    public void testGetRandomX509CertificateFromFolder_2args() throws Exception {        
        
        X509Certificate result = X509Factory.getRandomX509CertificateFromFolder(certificateFolder, keyFolder);
        assertNotNull(result);
    }

    /**
     * Test of getRandomX509CertificateFromFolder method, of class X509Factory.
     */
    @Test
    public void testGetRandomX509CertificateFromFolder_3args() throws Exception {        
        X509Certificate result = X509Factory.getRandomX509CertificateFromFolder(certificateFolder, keyFolder, KeyType.RSA);
        assertNotNull(result);
        
        X509Certificate result1 = X509Factory.getRandomX509CertificateFromFolder(certificateFolder, keyFolder, null);
        assertNotNull(result1);
        
        X509Certificate result2 = X509Factory.getRandomX509CertificateFromFolder(certificateFolder, null, null);
        assertNotNull(result2);
    }
    
    
}
