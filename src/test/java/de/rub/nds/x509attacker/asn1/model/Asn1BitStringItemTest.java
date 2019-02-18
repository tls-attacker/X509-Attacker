package de.rub.nds.x509attacker.asn1.model;

import org.junit.Test;

import static org.junit.Assert.*;

public class Asn1BitStringItemTest {

    @Test
    public void testAsn1BitStringEncoding() {
        Asn1BitString asn1BitString = new Asn1BitString();
        Asn1BitString.Asn1BitStringItem asn1BitStringValue = new Asn1BitString.Asn1BitStringItem();
        byte[] encoded;

        // bit string is 0110 1110 0101 1101 11
        asn1BitStringValue.setAsn1BitStringValue(new byte[]{0x6e, 0x5d, (byte) 0xc0});
        asn1BitStringValue.setAsn1NumberOfUnusedBits(6);
        asn1BitString.addField(asn1BitStringValue);
        encoded = asn1BitString.encode();
        assertArrayEquals(new byte[]{0x03, 0x04, 0x06, 0x6e, 0x5d, (byte) 0xc0}, encoded);
    }

    @Test
    public void testAsn1BitStringEncoding2() {
        Asn1BitString asn1BitString = new Asn1BitString();
        Asn1BitString.Asn1BitStringItem asn1BitStringValue1 = new Asn1BitString.Asn1BitStringItem();
        Asn1BitString.Asn1BitStringItem asn1BitStringValue2 = new Asn1BitString.Asn1BitStringItem();
        byte[] encoded;

        // bit string is 0110 1110 0101 1101
        asn1BitStringValue1.setAsn1BitStringValue(new byte[]{0x6e, 0x5d});
        asn1BitStringValue1.setAsn1NumberOfUnusedBits(0);

        // bit string is 11
        asn1BitStringValue2.setAsn1BitStringValue(new byte[]{(byte) 0xc0});
        asn1BitStringValue2.setAsn1NumberOfUnusedBits(6);

        asn1BitString.addField(asn1BitStringValue1);
        asn1BitString.addField(asn1BitStringValue2);
        encoded = asn1BitString.encode();
        assertArrayEquals(new byte[]{0x23, 0x09, 0x03, 0x03, 0x00, 0x6e, 0x5d, 0x03, 0x02, 0x06, (byte) 0xc0}, encoded);
    }
}