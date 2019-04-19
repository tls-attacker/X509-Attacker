package de.rub.nds.asn1.encoder;

import de.rub.nds.asn1.model.Asn1PrimitiveUtcTime;

public class Asn1PrimitiveUtcTimeEncoder extends Asn1FieldEncoder {

    private final Asn1PrimitiveUtcTime asn1PrimitiveUtcTime;

    public Asn1PrimitiveUtcTimeEncoder(Asn1PrimitiveUtcTime asn1PrimitiveUtcTime) {
        super(asn1PrimitiveUtcTime);
        this.asn1PrimitiveUtcTime = asn1PrimitiveUtcTime;
    }

    @Override
    public byte[] encode() {
        this.updateModifiableVariables();
        this.encodePrimitiveUtcTime();
        return super.encode();
    }

    private void updateModifiableVariables() {
        String utcTimeValue = this.asn1PrimitiveUtcTime.getUtcTimeValue();
        this.asn1PrimitiveUtcTime.setUtcTimeValueModificationValue(utcTimeValue);
    }

    private void encodePrimitiveUtcTime() {
        byte[] content = this.asn1PrimitiveUtcTime.getFinalUtcTimeValue().getBytes();
        this.asn1PrimitiveUtcTime.setContent(content);
    }
}
