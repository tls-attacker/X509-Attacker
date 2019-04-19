package de.rub.nds.asn1.encoder;

import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;

public class Asn1PrimitiveOctetStringEncoder extends Asn1FieldEncoder {

    private final Asn1PrimitiveOctetString asn1PrimitiveOctetString;

    public Asn1PrimitiveOctetStringEncoder(Asn1PrimitiveOctetString asn1PrimitiveOctetString) {
        super(asn1PrimitiveOctetString);
        this.asn1PrimitiveOctetString = asn1PrimitiveOctetString;
    }

    @Override
    public byte[] encode() {
        this.updateModifiableVariables();
        this.encodePrimitiveOctetString();
        return super.encode();
    }

    private void updateModifiableVariables() {
        byte[] octetStringValue = this.asn1PrimitiveOctetString.getOctetStringValue();
        this.asn1PrimitiveOctetString.setOctetStringValueModificationValue(octetStringValue);
    }

    private void encodePrimitiveOctetString() {
        byte[] content = this.asn1PrimitiveOctetString.getFinalOctetStringValue();
        this.asn1PrimitiveOctetString.setContent(content);
    }
}
