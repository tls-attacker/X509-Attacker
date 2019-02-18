package de.rub.nds.x509attacker.asn1.model;

import org.junit.Test;

import static org.junit.Assert.*;

public class Asn1Ia5StringItemTest {

    @Test
    public void testAsn1Ia5StringEncoding() {
        Asn1Ia5String asn1Ia5String = new Asn1Ia5String();
        Asn1Ia5String.Asn1Ia5StringItem asn1Ia5StringItem = new Asn1Ia5String.Asn1Ia5StringItem();
        byte[] encoded;

        // string "test1@rsa.com"
        asn1Ia5StringItem.setAsn1Ia5StringValue("test1@rsa.com");
        asn1Ia5String.addField(asn1Ia5StringItem);
        encoded = asn1Ia5String.encode();
        assertArrayEquals(new byte[]{0x16, 0x0d, 0x74, 0x65, 0x73, 0x74, 0x31, 0x40, 0x72, 0x73, 0x61, 0x2e, 0x63, 0x6f, 0x6d}, encoded);
    }
}