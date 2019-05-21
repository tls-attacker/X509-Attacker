package de.rub.nds.asn1.encoder;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.encoder.encodingoptions.Asn1EncodingOptions;
import de.rub.nds.asn1.encoder.encodingoptions.DefaultX509EncodingOptions;
import de.rub.nds.x509attacker.linker.Linker;

import java.util.LinkedList;
import java.util.List;

public class Asn1EncoderForX509 {

    public static byte[] encode(final Linker linker, final List<Asn1Encodable> asn1Encodables) {
        Asn1EncodingOptions asn1EncodingOptions = new DefaultX509EncodingOptions(EncodeTarget.FOR_ALL, linker);
        Asn1Encoder asn1Encoder = new Asn1Encoder(asn1EncodingOptions, asn1Encodables);
        return asn1Encoder.encode();
    }

    public static byte[] encode(final Linker linker, final Asn1Encodable asn1Encodable) {
        List<Asn1Encodable> asn1Encodables = new LinkedList<>();
        asn1Encodables.add(asn1Encodable);
        return encode(linker, asn1Encodables);
    }

    public static byte[] encodeForSignature(final Linker linker, final List<Asn1Encodable> asn1Encodables) {
        Asn1EncodingOptions asn1EncodingOptions = new DefaultX509EncodingOptions(EncodeTarget.FOR_SIGNATURE_ONLY, linker);
        Asn1Encoder asn1Encoder = new Asn1Encoder(asn1EncodingOptions, asn1Encodables);
        return asn1Encoder.encode();
    }

    public static byte[] encodeForSignature(final Linker linker, final Asn1Encodable asn1Encodable) {
        List<Asn1Encodable> asn1Encodables = new LinkedList<>();
        asn1Encodables.add(asn1Encodable);
        return encodeForSignature(linker, asn1Encodables);
    }

    public static byte[] encodeForCertificate(final Linker linker, final List<Asn1Encodable> asn1Encodables) {
        Asn1EncodingOptions asn1EncodingOptions = new DefaultX509EncodingOptions(EncodeTarget.FOR_CERTIFICATE_ONLY, linker);
        Asn1Encoder asn1Encoder = new Asn1Encoder(asn1EncodingOptions, asn1Encodables);
        return asn1Encoder.encode();
    }

    public static byte[] encodeForCertificate(final Linker linker, final Asn1Encodable asn1Encodable) {
        List<Asn1Encodable> asn1Encodables = new LinkedList<>();
        asn1Encodables.add(asn1Encodable);
        return encodeForCertificate(linker, asn1Encodables);
    }
}
