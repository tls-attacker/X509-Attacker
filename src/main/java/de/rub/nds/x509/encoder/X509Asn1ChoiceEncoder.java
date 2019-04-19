package de.rub.nds.x509.encoder;

import de.rub.nds.asn1.encoder.Asn1ChoiceEncoder;
import de.rub.nds.x509.encoder.X509EncoderManager;
import de.rub.nds.x509.model.asn1.X509Asn1Choice;

public class X509Asn1ChoiceEncoder extends Asn1ChoiceEncoder {

    private final X509Asn1Choice x509Asn1Choice;

    public X509Asn1ChoiceEncoder(final X509Asn1Choice x509Asn1Choice) {
        super(x509Asn1Choice);
        this.x509Asn1Choice = x509Asn1Choice;
    }

    @Override
    public byte[] encode() {
        byte[] encoded = new byte[0];
        switch (X509EncoderManager.getEncodeMode()) {
            case X509EncoderManager.ENCODE_NONE:
                break;

            case X509EncoderManager.ENCODE_FOR_CERTIFICATE:
                if (this.x509Asn1Choice.isExcludeFromCertificate()) {
                    break;
                }

            case X509EncoderManager.ENCODE_FOR_SIGNATURE:
                if (this.x509Asn1Choice.isExcludeFromSignature()) {
                    break;
                }

            case X509EncoderManager.ENCODE_ALL:
                encoded = super.encode();
        }
        return encoded;
    }
}
