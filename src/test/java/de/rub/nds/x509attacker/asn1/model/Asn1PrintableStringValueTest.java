package de.rub.nds.x509attacker.asn1.model;

import org.junit.Test;

import static org.junit.Assert.*;

public class Asn1PrintableStringValueTest {

    @Test
    public void testAsn1PrintableStringEncoding() {
        Asn1PrintableString asn1PrintableString = new Asn1PrintableString();
        Asn1PrintableString.Asn1PrintableStringValue asn1PrintableStringValue = new Asn1PrintableString.Asn1PrintableStringValue();
        byte[] encoded;

        // string "Test User 1"
        asn1PrintableStringValue.setAsn1PrintableStringValue("Test User 1");
        asn1PrintableString.addField(asn1PrintableStringValue);
        encoded = asn1PrintableString.encode();
        assertArrayEquals(new byte[]{0x13, 0x0b, 0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 0x73, 0x65, 0x72, 0x20, 0x31}, encoded);
    }
}