package de.rub.nds.x509attacker.asn1;

public enum Asn1TagClass {
    UNIVERSAL(0, "Universal"),
    APPLICATION(1, "Application"),
    CONTEXT_SPECIFIC(2, "Context-specific"),
    PRIVATE(3, "Private");

    private final int tagClass;
    private final String stringValue;

    Asn1TagClass(int tagClass, String stringValue) {
        this.tagClass = tagClass;
        this.stringValue = stringValue;
    }

    public static Asn1TagClass fromString(String stringValue) {
        Asn1TagClass result = null;
        for (Asn1TagClass currentAsn1TagClass : Asn1TagClass.values()) {
            if (stringValue != null && stringValue.equalsIgnoreCase(currentAsn1TagClass.toString())) {
                result = currentAsn1TagClass;
            }
        }
        if (result == null) {
            throw new RuntimeException("Tag class is \"" + stringValue + "\", but should be one of: universal, application, context-specific, private.");
        }
        return result;
    }

    public static Asn1TagClass fromByte(byte byteVal) {
        Asn1TagClass result = null;
        for (Asn1TagClass currentAsn1TagClass : Asn1TagClass.values()) {
            if (byteVal == currentAsn1TagClass.getIntValue()) {
                result = currentAsn1TagClass;
            }
        }
        if (result == null) {
            throw new RuntimeException("Tag class is \"" + byteVal + "\", but should be one of: 0, 1, 2, 3.");
        }
        return result;
    }

    public int getIntValue() {
        return tagClass;
    }

    @Override
    public String toString() {
        return this.stringValue;
    }
}
