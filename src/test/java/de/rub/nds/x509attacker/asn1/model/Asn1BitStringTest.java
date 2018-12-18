package de.rub.nds.x509attacker.asn1.model;

import org.junit.Test;

import static org.junit.Assert.*;

public class Asn1BitStringTest {

    @Test
    public void testAsn1BitStringEncoding() {
        Asn1BitString asn1BitString = new Asn1BitString();
        byte[] encoded;

        // bit string is 0110 1110 0101 1101 11
        asn1BitString.setAsn1BitStringValue(new byte[]{0x6e, 0x5d, (byte) 0xc0});
        asn1BitString.setAsn1NumberOfUnusedBits(6);
        encoded = asn1BitString.encode();
        assertArrayEquals(new byte[]{0x03, 0x04, 0x06, 0x6e, 0x5d, (byte) 0xc0}, encoded);
    }
}