package de.rub.nds.asn1.encoder;

import de.rub.nds.asn1.model.Asn1PrimitiveT61String;

public class Asn1PrimitiveT61StringEncoder extends Asn1FieldEncoder {

    private final Asn1PrimitiveT61String asn1PrimitiveT61String;

    public Asn1PrimitiveT61StringEncoder(Asn1PrimitiveT61String asn1PrimitiveT61String) {
        super(asn1PrimitiveT61String);
        this.asn1PrimitiveT61String = asn1PrimitiveT61String;
    }

    @Override
    public byte[] encode() {
        this.updateModifiableVariables();
        this.encodePrimitiveT61String();
        return super.encode();
    }

    private void updateModifiableVariables() {
        String t61StringValue = this.asn1PrimitiveT61String.getT61StringValue();
        this.asn1PrimitiveT61String.setT61StringValueModificationValue(t61StringValue);
    }

    private void encodePrimitiveT61String() {
        byte[] content = this.asn1PrimitiveT61String.getFinalT61StringValue().getBytes();
        // Todo: Character set conversion
        this.asn1PrimitiveT61String.setContent(content);
    }
}
