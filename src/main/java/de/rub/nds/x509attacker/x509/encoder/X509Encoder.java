package de.rub.nds.x509attacker.x509.encoder;

import de.rub.nds.x509attacker.asn1.model.Asn1RawField;

public class X509Encoder {

    private static X509Encoder reference = null;

    private EncodeMode encodeMode = EncodeMode.ALL;

    private X509Encoder() {

    }

    public static X509Encoder getReference() {
        if (reference == null) {
            synchronized (X509Encoder.class) {
                if (reference == null) {
                    reference = new X509Encoder();
                }
            }
        }
        return reference;
    }

    public EncodeMode getEncodeMode() {
        return encodeMode;
    }

    public void setEncodeMode(EncodeMode encodeMode) {
        this.encodeMode = encodeMode;
    }

    public byte[] encode(Asn1RawField field) {
        return field.encode();
    }
}
