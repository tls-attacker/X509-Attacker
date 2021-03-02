
package de.rub.nds.x509attacker.identifiermap;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Container;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509attacker.exceptions.X509ModificationException;
import de.rub.nds.x509attacker.x509.X509Certificate;
import de.rub.nds.x509attacker.helper.X509Factory;
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;
import org.junit.Ignore;

/**
 *
 * @author josh
 */
public class IdentifierMapTest {
    
    
    
    private X509Certificate cert;
    private IdentifierMap identifierMap;
    
    public IdentifierMapTest() {
    }   
    
    @Before
    public void setUp() throws IOException, JAXBException, XMLStreamException {
        cert = X509Factory.getRandomX509CertificateFromFolder(new File("resources/x509Certificates"), new File("resources/keys")); 
        identifierMap = cert.getIdentifierMap();
    }    

    /**
     * Test of getMap method, of class IdentifierMap.
     */
    @Test
    public void testGetMap() {
        Map<String, Asn1Encodable> map = identifierMap.getMap();
        assertNotNull(map);
        assertTrue(map.size() > 1);
    }

    /**
     * Test of setMap method, of class IdentifierMap.
     */
    @Test
    public void testSetMap() {
        Map<String, Asn1Encodable> newHashMap = new HashMap<>();
        newHashMap.put("/test", new Asn1Integer());
        
        identifierMap.setMap(newHashMap);
        
        Map<String, Asn1Encodable> map = identifierMap.getMap();
        assertNotNull(map);
        assertTrue(map.size() == 1);
        
    }

    /**
     * Test of getElementByIDPath method, of class IdentifierMap.
     */
    @Test
    public void testGetElementByIDPath() {
        assertTrue(identifierMap.getElementByIDPath("/certificate").getClass().equals(Asn1Sequence.class) );
        assertNull(identifierMap.getElementByIDPath("/cert"));
        assertTrue(identifierMap.getElementByIDPath("certificate").getClass().equals(Asn1Sequence.class) );
        assertTrue(identifierMap.getElementByIDPath("/certificate/").getClass().equals(Asn1Sequence.class) );
        assertNull(identifierMap.getElementByIDPath(""));
        
    }

    /**
     * Test of getElementsByID method, of class IdentifierMap.
     */
    @Test
    public void testGetElementsByID() {
        assertTrue(identifierMap.getElementsByID("certificate").size() >= 1 );
        assertNull(identifierMap.getElementsByID("cert"));
        assertNull(identifierMap.getElementsByID(""));
    }

    /**
     * Test of getElementsByType method, of class IdentifierMap.
     */
    @Test
    public void testGetElementsByType() {
        assertTrue(identifierMap.getElementsByType("Certificate").size() >= 1 );
        assertNull(identifierMap.getElementsByType("cert"));
        assertNull(identifierMap.getElementsByType(""));
    }

    /**
     * Test of getElementsByClass method, of class IdentifierMap.
     */
    @Test
    public void testGetElementsByClass() {
        assertTrue(identifierMap.getElementsByClass(Asn1Sequence.class).size() >= 1 );
        assertTrue(identifierMap.getElementsByClass(Asn1Container.class).size() >= 1 );
        assertNull(identifierMap.getElementsByClass(Integer.class));
        assertNull(identifierMap.getElementsByClass(null));
    }

    /**
     * Test of getIDPathByElement method, of class IdentifierMap.
     */
    @Test
    public void testGetIDPathByElement() {
        Asn1Encodable certificateAsn1Sequence = identifierMap.getElementByIDPath("/certificate");
        assertEquals(identifierMap.getIDPathByElement(certificateAsn1Sequence),"/certificate");
        assertEquals(identifierMap.getIDPathByElement(null), "");
        assertEquals(identifierMap.getIDPathByElement(new Asn1Sequence()), "");
    }

    /**
     * Test of getIDPathsByID method, of class IdentifierMap.
     */
    @Test
    public void testGetIDPathsByID() {
        assertTrue(identifierMap.getIDPathsByID("certificate").size() >= 1 );
        assertNull(identifierMap.getIDPathsByID("cert"));
        assertNull(identifierMap.getIDPathsByID(""));
    }

    /**
     * Test of getIDPathsByType method, of class IdentifierMap.
     */
    @Test
    public void testGetIDPathsByType() {
        assertTrue(identifierMap.getIDPathsByType("Certificate").size() >= 1 );
        assertNull(identifierMap.getIDPathsByType("cert"));
        assertNull(identifierMap.getIDPathsByType(""));
    }

    /**
     * Test of getIDPathsByClass method, of class IdentifierMap.
     */
    @Test
    public void testGetIDPathsByClass() {
        assertTrue(identifierMap.getIDPathsByClass(Asn1Sequence.class).size() >= 1 );
        assertTrue(identifierMap.getIDPathsByClass(Asn1Container.class).size() >= 1 );
        assertNull(identifierMap.getIDPathsByClass(Integer.class));
        assertNull(identifierMap.getIDPathsByClass(null));
    }

    /**
     * Test of getCopyByIDPath method, of class IdentifierMap.
     */
    @Ignore("Not yet implemented")
    @Test
    public void testGetCopyByIDPath() {
        fail("The test case is a prototype.");
    }

    /**
     * Test of getCopyByElement method, of class IdentifierMap.
     */
    @Ignore("Not yet implemented")
    @Test
    public void testGetCopyByElement() {
        fail("The test case is a prototype.");
    }

    /**
     * Test of setElementByIDPath method, of class IdentifierMap.
     */
    @Ignore("Not yet implemented")
    @Test
    public void testSetElementByIDPath() throws Exception {
        fail("The test case is a prototype.");
    }

    /**
     * Test of removeElementByIDPath method, of class IdentifierMap.
     */
    @Test(expected = X509ModificationException.class)
    public void testRemoveElementByIDPath_noParent() throws Exception {
        identifierMap.removeElementByIDPath("/certificate");
    }
    
}
