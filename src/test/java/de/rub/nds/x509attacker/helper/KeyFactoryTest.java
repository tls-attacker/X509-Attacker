
package de.rub.nds.x509attacker.helper;

import de.rub.nds.signatureengine.keyparsers.KeyType;
import java.io.File;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author josh
 */
public class KeyFactoryTest {
    
    private File keyFolder;
    
    public KeyFactoryTest() {
    }
    
    @Before
    public void setUp() throws Exception {
        keyFolder = new File("resources/keys");
    }

    /**
     * Test of getRandomKeyFileFromFolder method, of class X509Factory.
     */
    @Test
    public void testGetRandomKeyFileFromFolder() throws Exception {
        File result = KeyFactory.getRandomKeyFileFromFolder(keyFolder, null);
        assertNotNull(result);
        assertTrue(result.getAbsolutePath().contains(keyFolder.getAbsolutePath()));
        
    }
    
    
    /**
     * Test of getRandomKeyFileFromFolder method, of class X509Factory.
     */
    @Test
    public void testGetRandomKeyFileFromFolder_File() throws Exception {
        File result = KeyFactory.getRandomKeyFileFromFolder(keyFolder, null);
        assertNotNull(result);
        assertTrue(result.getAbsolutePath().contains(keyFolder.getAbsolutePath()));
    }

    /**
     * Test of getRandomKeyFileFromFolder method, of class X509Factory.
     */
    @Test
    public void testGetRandomKeyFileFromFolder_File_KeyType() throws Exception {
        File result = KeyFactory.getRandomKeyFileFromFolder(keyFolder, KeyType.RSA);
        assertNotNull(result);
        assertTrue(result.getAbsolutePath().contains(keyFolder.getAbsolutePath()));
    }
    
}
