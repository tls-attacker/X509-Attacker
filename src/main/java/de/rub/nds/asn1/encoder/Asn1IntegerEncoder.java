package de.rub.nds.asn1.encoder;

import de.rub.nds.asn1.model.Asn1Integer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;

public class Asn1IntegerEncoder extends Asn1FieldEncoder {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Asn1Integer asn1Integer;

    public Asn1IntegerEncoder(Asn1Integer asn1Integer) {
        super(asn1Integer);
        this.asn1Integer = asn1Integer;
    }

    @Override
    public byte[] encode() {
        this.updateModifiableVariables();
        this.encodeInteger();
        return super.encode();
    }

    private void updateModifiableVariables() {
        BigInteger integerValue = this.asn1Integer.getIntegerValue();
        this.asn1Integer.setIntegerValueModificationValue(integerValue);
    }

    private void encodeInteger() {
        byte[] content = this.asn1Integer.getFinalIntegerValue().toByteArray();
        this.asn1Integer.setContent(content);
    }
}
