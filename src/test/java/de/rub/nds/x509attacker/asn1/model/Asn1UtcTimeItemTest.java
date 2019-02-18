package de.rub.nds.x509attacker.asn1.model;

import org.junit.Test;

import static org.junit.Assert.*;

public class Asn1UtcTimeItemTest {

    @Test
    public void testAsn1UtcTimeEncoding() {
        Asn1UtcTime asn1UtcTime = new Asn1UtcTime();
        Asn1UtcTime.Asn1UtcTimeItem asn1UtcTimeItem = new Asn1UtcTime.Asn1UtcTimeItem();
        byte[] encoded;

        asn1UtcTimeItem.setAsn1UtcTimeValue("910506164540-0700");
        asn1UtcTime.addField(asn1UtcTimeItem);
        encoded = asn1UtcTime.encode();
        assertArrayEquals(new byte[]{0x17, 0x11, 0x39, 0x31, 0x30, 0x35, 0x30, 0x36, 0x31, 0x36, 0x34, 0x35, 0x34, 0x30, 0x2D, 0x30, 0x37, 0x30, 0x30}, encoded);
    }
}