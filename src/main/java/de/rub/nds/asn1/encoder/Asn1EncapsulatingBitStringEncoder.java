package de.rub.nds.asn1.encoder;

import de.rub.nds.asn1.model.Asn1EncapsulatingBitString;
import de.rub.nds.asn1.model.Asn1Encodable;

import java.util.List;

public class Asn1EncapsulatingBitStringEncoder extends Asn1FieldContainerEncoder {

    private final Asn1EncapsulatingBitString asn1EncapsulatingBitString;

    public Asn1EncapsulatingBitStringEncoder(Asn1EncapsulatingBitString asn1EncapsulatingBitString) {
        super(asn1EncapsulatingBitString);
        this.asn1EncapsulatingBitString = asn1EncapsulatingBitString;
    }

    @Override
    public byte[] encode() {
        return super.encode();
    }

    @Override
    protected void encodeChildren() {
        byte[] content = new byte[] { 0 }; // Number of unused bits is zero
        List<Asn1Encodable> children = this.asn1EncapsulatingBitString.getChildren();
        for(Asn1Encodable child : children) {
            content = merge(content, child.getEncoder().encode());
        }
        this.asn1EncapsulatingBitString.setContent(content);
    }
}
