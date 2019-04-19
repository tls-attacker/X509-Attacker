package de.rub.nds.x509.encoder;

import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.asn1.model.Asn1Field;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import de.rub.nds.x509.model.X509Field;

public class X509FieldEncoder extends Asn1Encoder {

    private static final Logger LOGGER = LogManager.getLogger();

    private final X509Field x509Field;

    public X509FieldEncoder(X509Field x509Field) {
        this.x509Field = x509Field;
    }

    @Override
    public byte[] encode() {
        byte[] encoded = new byte[0];
        switch (X509EncoderManager.getEncodeMode()) {
            case X509EncoderManager.ENCODE_NONE:
                break;

            case X509EncoderManager.ENCODE_FOR_CERTIFICATE:
                if (this.x509Field.isExcludeFromCertificate()) {
                    break;
                }

            case X509EncoderManager.ENCODE_FOR_SIGNATURE:
                if (this.x509Field.isExcludeFromSignature()) {
                    break;
                }

            case X509EncoderManager.ENCODE_ALL:
                encoded = this.x509Field.getAsn1Field().getEncoder().encode();
        }
        return encoded;
    }

    @Override
    public Asn1Field encodeAndGetAsn1Field() {
        return this.x509Field.getAsn1Field().getEncoder().encodeAndGetAsn1Field();
    }
}
