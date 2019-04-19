package de.rub.nds.asn1.encoder;

import de.rub.nds.asn1.model.Asn1PrimitiveUtf8String;

public class Asn1PrimitiveUtf8StringEncoder extends Asn1FieldEncoder {

    private final Asn1PrimitiveUtf8String asn1PrimitiveUtf8String;

    public Asn1PrimitiveUtf8StringEncoder(Asn1PrimitiveUtf8String asn1PrimitiveUtf8String) {
        super(asn1PrimitiveUtf8String);
        this.asn1PrimitiveUtf8String = asn1PrimitiveUtf8String;
    }

    @Override
    public byte[] encode() {
        this.updateModifiableVariables();
        this.encodePrimitiveUtf8String();
        return super.encode();
    }

    private void updateModifiableVariables() {
        String utf8StringValue = this.asn1PrimitiveUtf8String.getUtf8StringValue();
        this.asn1PrimitiveUtf8String.setUtf8StringValueModificationValue(utf8StringValue);
    }

    private void encodePrimitiveUtf8String() {
        byte[] content = this.asn1PrimitiveUtf8String.getFinalUtf8StringValue().getBytes();
        this.asn1PrimitiveUtf8String.setContent(content);
    }
}
