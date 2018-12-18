package de.rub.nds.x509attacker.asn1.model;

import org.junit.Test;

import static org.junit.Assert.*;

public class Asn1PrintableStringTest {

    @Test
    public void testAsn1PrintableStringEncoding() {
        Asn1PrintableString asn1Ia5String = new Asn1PrintableString();
        byte[] encoded;

        // string "Test User 1"
        asn1Ia5String.setAsn1PrintableStringValue("Test User 1");
        encoded = asn1Ia5String.encode();
        assertArrayEquals(new byte[]{0x13, 0x0b, 0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 0x73, 0x65, 0x72, 0x20, 0x31}, encoded);
    }
}