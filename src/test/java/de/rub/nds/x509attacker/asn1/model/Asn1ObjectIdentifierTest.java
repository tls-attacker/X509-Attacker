package de.rub.nds.x509attacker.asn1.model;

import org.junit.Test;

import static org.junit.Assert.*;

public class Asn1ObjectIdentifierTest {

    @Test
    public void testAsn1ObjectIdentifierEncoding() {
        Asn1ObjectIdentifier objectIdentifier = new Asn1ObjectIdentifier();
        byte[] encoded;

        objectIdentifier.setAsn1ObjectIdentifierValue("1.2.840.113549");
        encoded = objectIdentifier.encode();
        assertArrayEquals(new byte[]{0x06, 0x06, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d}, encoded);
    }
}