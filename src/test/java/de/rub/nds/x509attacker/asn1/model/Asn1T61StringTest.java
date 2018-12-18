package de.rub.nds.x509attacker.asn1.model;

import org.junit.Test;

import static org.junit.Assert.*;

public class Asn1T61StringTest {

    @Test
    public void testAsn1T61StringEncoding() {
        Asn1T61String asn1T61String = new Asn1T61String();
        byte[] encoded;

        // string "Test User 1"
        asn1T61String.setAsn1T61StringValue("cl'es publiques");
        encoded = asn1T61String.encode();
        assertArrayEquals(new byte[]{0x14, 0x0f, 0x63, 0x6c, (byte) 0xc2, 0x65, 0x73, 0x20, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x71, 0x75, 0x65, 0x73}, encoded);
    }
}