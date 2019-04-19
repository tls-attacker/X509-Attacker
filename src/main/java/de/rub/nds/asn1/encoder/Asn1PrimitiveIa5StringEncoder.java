package de.rub.nds.asn1.encoder;

import de.rub.nds.asn1.model.Asn1PrimitiveIa5String;

public class Asn1PrimitiveIa5StringEncoder extends Asn1FieldEncoder {

    private final Asn1PrimitiveIa5String asn1PrimitiveIa5String;

    public Asn1PrimitiveIa5StringEncoder(Asn1PrimitiveIa5String asn1PrimitiveIa5String) {
        super(asn1PrimitiveIa5String);
        this.asn1PrimitiveIa5String = asn1PrimitiveIa5String;
    }

    @Override
    public byte[] encode() {
        this.updateModifiableVariables();
        this.encodePrimitiveIa5String();
        return super.encode();
    }

    private void updateModifiableVariables() {
        String ia5StringValue = this.asn1PrimitiveIa5String.getIa5StringValue();
        this.asn1PrimitiveIa5String.setIa5StringValueModificationValue(ia5StringValue);
    }

    private void encodePrimitiveIa5String() {
        byte[] content = this.asn1PrimitiveIa5String.getFinalIa5StringValue().getBytes();
        this.asn1PrimitiveIa5String.setContent(content);
    }
}
