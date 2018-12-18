package de.rub.nds.x509attacker.asn1.model;

import org.junit.Test;

import static org.junit.Assert.*;

public class Asn1OctetStringTest {

    @Test
    public void testAsn1ObjectStringEncoding() {
        Asn1OctetString octetString = new Asn1OctetString();
        byte[] encoded;

        octetString.setAsn1OctetStringValue(new byte[]{0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef});
        encoded = octetString.encode();
        assertArrayEquals(new byte[]{0x04, 0x08, 0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef}, encoded);
    }
}