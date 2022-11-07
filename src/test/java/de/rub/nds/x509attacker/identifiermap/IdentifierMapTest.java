/**
 * X.509-Attacker - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509attacker.identifiermap;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Container;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509attacker.exceptions.X509ModificationException;
import de.rub.nds.x509attacker.helper.X509Factory;
import de.rub.nds.x509attacker.registry.Registry;
import de.rub.nds.x509attacker.x509.X509Certificate;
import jakarta.xml.bind.JAXBException;
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.xml.stream.XMLStreamException;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class IdentifierMapTest {

    private X509Certificate cert;
    private IdentifierMap identifierMap;

    public IdentifierMapTest() {
    }

    @BeforeEach
    public void setUp() throws IOException, JAXBException, XMLStreamException {
        Registry.getInstance();
        cert = X509Factory.getRandomX509CertificateFromFolder(new File("resources/x509Certificates"),
            new File("resources/keys"));
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
        assertEquals(1, map.size());

    }

    /**
     * Test of getElementByIDPath method, of class IdentifierMap.
     */
    @Test
    public void testGetElementByIDPath() {
        assertEquals(identifierMap.getElementByIDPath("/certificate").getClass(), Asn1Sequence.class);
        assertNull(identifierMap.getElementByIDPath("/cert"));
        assertEquals(identifierMap.getElementByIDPath("certificate").getClass(), Asn1Sequence.class);
        assertEquals(identifierMap.getElementByIDPath("/certificate/").getClass(), Asn1Sequence.class);
        assertNull(identifierMap.getElementByIDPath(""));

    }

    /**
     * Test of getElementsByID method, of class IdentifierMap.
     */
    @Test
    public void testGetElementsByID() {
        assertTrue(identifierMap.getElementsByID("certificate").size() >= 1);
        assertNull(identifierMap.getElementsByID("cert"));
        assertNull(identifierMap.getElementsByID(""));
    }

    /**
     * Test of getElementsByType method, of class IdentifierMap.
     */
    @Test
    public void testGetElementsByType() {
        assertTrue(identifierMap.getElementsByType("Certificate").size() >= 1);
        assertNull(identifierMap.getElementsByType("cert"));
        assertNull(identifierMap.getElementsByType(""));
    }

    /**
     * Test of getElementsByClass method, of class IdentifierMap.
     */
    @Test
    public void testGetElementsByClass() {
        assertTrue(identifierMap.getElementsByClass(Asn1Sequence.class).size() >= 1);
        assertTrue(identifierMap.getElementsByClass(Asn1Container.class).size() >= 1);
        assertNull(identifierMap.getElementsByClass(Integer.class));
        assertNull(identifierMap.getElementsByClass(null));
    }

    /**
     * Test of getIDPathByElement method, of class IdentifierMap.
     */
    @Test
    public void testGetIDPathByElement() {
        Asn1Encodable certificateAsn1Sequence = identifierMap.getElementByIDPath("/certificate");
        assertEquals(identifierMap.getIDPathByElement(certificateAsn1Sequence), "/certificate");
        assertEquals(identifierMap.getIDPathByElement(null), "");
        assertEquals(identifierMap.getIDPathByElement(new Asn1Sequence()), "");
    }

    /**
     * Test of getIDPathsByID method, of class IdentifierMap.
     */
    @Test
    public void testGetIDPathsByID() {
        assertTrue(identifierMap.getIDPathsByID("certificate").size() >= 1);
        assertNull(identifierMap.getIDPathsByID("cert"));
        assertNull(identifierMap.getIDPathsByID(""));
    }

    /**
     * Test of getIDPathsByType method, of class IdentifierMap.
     */
    @Test
    public void testGetIDPathsByType() {
        assertTrue(identifierMap.getIDPathsByType("Certificate").size() >= 1);
        assertNull(identifierMap.getIDPathsByType("cert"));
        assertNull(identifierMap.getIDPathsByType(""));
    }

    /**
     * Test of getIDPathsByClass method, of class IdentifierMap.
     */
    @Test
    public void testGetIDPathsByClass() {
        assertTrue(identifierMap.getIDPathsByClass(Asn1Sequence.class).size() >= 1);
        assertTrue(identifierMap.getIDPathsByClass(Asn1Container.class).size() >= 1);
        assertNull(identifierMap.getIDPathsByClass(Integer.class));
        assertNull(identifierMap.getIDPathsByClass(null));
    }

    /**
     * Test of removeElementByIDPath method, of class IdentifierMap.
     */
    @Test
    public void testRemoveElementByIDPath_noParent() {
        assertThrowsExactly(X509ModificationException.class, () -> identifierMap.removeElementByIDPath("/certificate"));
    }

}
