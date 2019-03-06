package de.rub.nds.x509attacker.asn1.model;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

public class Asn1T61StringItemTest {

    @Test
    public void testAsn1T61StringEncoding() {
        Asn1T61String asn1T61String = new Asn1T61String();
        Asn1T61String.Asn1T61StringItem asn1T61StringItem = new Asn1T61String.Asn1T61StringItem();
        byte[] encoded;

        // string "cl'es publiques"
        asn1T61StringItem.setAsn1T61StringValue("cl'es publiques");
        asn1T61String.addField(asn1T61StringItem);
        encoded = asn1T61String.encode();
        assertArrayEquals(new byte[]{0x14, 0x0f, 0x63, 0x6c, (byte) 0xc2, 0x65, 0x73, 0x20, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x71, 0x75, 0x65, 0x73}, encoded);
        // Test fails since character conversion is not implemented yet.
    }
}