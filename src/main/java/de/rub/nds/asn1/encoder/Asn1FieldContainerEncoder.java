package de.rub.nds.asn1.encoder;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1FieldContainer;

import java.util.List;

public class Asn1FieldContainerEncoder extends Asn1FieldEncoder {

    private final Asn1FieldContainer asn1FieldContainer;

    public Asn1FieldContainerEncoder(Asn1FieldContainer asn1FieldContainer) {
        super(asn1FieldContainer);
        this.asn1FieldContainer = asn1FieldContainer;
    }

    @Override
    public byte[] encode() {
        this.encodeChildren();
        return super.encode();
    }

    protected void encodeChildren() {
        List<Asn1Encodable> children = this.asn1FieldContainer.getChildren();
        byte[] content = new byte[0];
        for(Asn1Encodable child : children) {
            content = merge(content, child.getEncoder().encode());
        }
        this.asn1FieldContainer.setContent(content);
    }
}
