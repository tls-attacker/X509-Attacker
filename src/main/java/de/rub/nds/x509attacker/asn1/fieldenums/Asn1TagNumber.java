package de.rub.nds.x509attacker.asn1.fieldenums;

public enum Asn1TagNumber {
    INTEGER(2, "INTEGER"),
    BIT_STRING(3, "BIT STRING"),
    OCTET_STRING(4, "OCTET STRING"),
    NULL(5, "NULL"),
    OBJECT_IDENTIFIER(6, "OBJECT IDENTIFIER"),
    SEQUENCE(16, "SEQUENCE"),
    SET(17, "SET"),
    PRINTABLESTRING(19, "PrintableString"),
    T61STRING(20, "T61String"),
    IA5STRING(22, "IA5String"),
    UTCTIME(23, "UTCTime");

    private final int tagNumber;
    private final String stringValue;

    Asn1TagNumber(int tagNumber, String stringValue) {
        this.tagNumber = tagNumber;
        this.stringValue = stringValue;
    }

    public static Asn1TagNumber fromString(String stringValue) {
        Asn1TagNumber result = null;
        for (Asn1TagNumber currentAsn1TagNumber : Asn1TagNumber.values()) {
            if (stringValue != null && stringValue.equalsIgnoreCase(currentAsn1TagNumber.toString())) {
                result = currentAsn1TagNumber;
            }
        }
        return result;
    }

    public int getIntValue() {
        return tagNumber;
    }

    @Override
    public String toString() {
        return this.stringValue;
    }

    public boolean isInstanceOf(String stringValue) {
        boolean result = false;
        if (stringValue != null && stringValue.equalsIgnoreCase(this.toString())) {
            result = true;
        }
        return result;
    }
}
