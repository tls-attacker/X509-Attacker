package de.rub.nds.x509attacker.asn1.model;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

public class Asn1IntegerTest {

    @Test
    public void testAsn1IntegerEncoding() {
        Asn1Integer asn1Integer;
        byte[] encoded;

        asn1Integer = new Asn1Integer();
        asn1Integer.setAsn1IntegerValue(0);
        encoded = asn1Integer.encode();
        assertArrayEquals(new byte[]{0x02, 0x01, 0x00}, encoded);

        asn1Integer = new Asn1Integer();
        asn1Integer.setAsn1IntegerValue(127);
        encoded = asn1Integer.encode();
        assertArrayEquals(new byte[]{0x02, 0x01, 0x7F}, encoded);

        asn1Integer = new Asn1Integer();
        asn1Integer.setAsn1IntegerValue(128);
        encoded = asn1Integer.encode();
        assertArrayEquals(new byte[]{0x02, 0x02, 0x00, (byte) 0x80}, encoded);

        asn1Integer = new Asn1Integer();
        asn1Integer.setAsn1IntegerValue(256);
        encoded = asn1Integer.encode();
        assertArrayEquals(new byte[]{0x02, 0x02, 0x01, 0x00}, encoded);

        asn1Integer = new Asn1Integer();
        asn1Integer.setAsn1IntegerValue(-128);
        encoded = asn1Integer.encode();
        assertArrayEquals(new byte[]{0x02, 0x01, (byte) 0x80}, encoded);

        asn1Integer = new Asn1Integer();
        asn1Integer.setAsn1IntegerValue(-129);
        encoded = asn1Integer.encode();
        assertArrayEquals(new byte[]{0x02, 0x02, (byte) 0xFF, 0x7F}, encoded);
    }
}