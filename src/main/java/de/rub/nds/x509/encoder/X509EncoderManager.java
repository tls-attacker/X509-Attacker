package de.rub.nds.x509.encoder;

import de.rub.nds.asn1.model.Asn1Encodable;

public class X509EncoderManager {

    public static final int ENCODE_NONE = 0;

    public static final int ENCODE_FOR_CERTIFICATE = 1 << 0; // 0x01

    public static final int ENCODE_FOR_SIGNATURE = 1 << 1; // 0x02

    public static final int ENCODE_ALL = ENCODE_FOR_CERTIFICATE | ENCODE_FOR_SIGNATURE;

    private static int encodeMode = ENCODE_ALL;

    public static void setEncodeMode(int encodeMode) {
        X509EncoderManager.encodeMode = encodeMode;
    }

    static int getEncodeMode() {
        return encodeMode;
    }

    public static byte[] encodeForSignature(Asn1Encodable asn1Encodable) {
        setEncodeMode(ENCODE_FOR_SIGNATURE);
        return asn1Encodable.getEncoder().encode();
    }

    public static byte[] encodeForCertificate(Asn1Encodable asn1Encodable) {
        setEncodeMode(ENCODE_FOR_CERTIFICATE);
        return asn1Encodable.getEncoder().encode();
    }
}
