package de.rub.nds.asn1.encoder;

import de.rub.nds.asn1.model.Asn1PrimitivePrintableString;

public class Asn1PrimitivePrintableStringEncoder extends Asn1FieldEncoder {

    private final Asn1PrimitivePrintableString asn1PrimitivePrintableString;

    public Asn1PrimitivePrintableStringEncoder(Asn1PrimitivePrintableString asn1PrimitivePrintableString) {
        super(asn1PrimitivePrintableString);
        this.asn1PrimitivePrintableString = asn1PrimitivePrintableString;
    }

    @Override
    public byte[] encode() {
        this.updateModifiableVariables();
        this.encodePrimitivePrintableString();
        return super.encode();
    }

    private void updateModifiableVariables() {
        String printableStringValue = this.asn1PrimitivePrintableString.getPrintableStringValue();
        this.asn1PrimitivePrintableString.setPrintableStringValueModificationValue(printableStringValue);
    }

    private void encodePrimitivePrintableString() {
        byte[] content = this.asn1PrimitivePrintableString.getFinalPrintableStringValue().getBytes();
        this.asn1PrimitivePrintableString.setContent(content);
    }
}
