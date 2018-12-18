package de.rub.nds.x509attacker.asn1.model;

import org.junit.Test;

import static org.junit.Assert.*;

public class Asn1NullTest {

    @Test
    public void testAsn1NullEncoding() {
        Asn1Null _null = new Asn1Null();
        byte[] encoded;

        encoded = _null.encode();
        assertArrayEquals(new byte[]{0x05, 0x00}, encoded);
    }
}