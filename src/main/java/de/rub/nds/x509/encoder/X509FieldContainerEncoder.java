package de.rub.nds.x509.encoder;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1FieldContainer;
import de.rub.nds.x509.model.X509FieldContainer;

import java.util.List;

public class X509FieldContainerEncoder extends X509FieldEncoder {

    private final X509FieldContainer x509FieldContainer;

    public X509FieldContainerEncoder(X509FieldContainer x509FieldContainer) {
        super(x509FieldContainer);
        this.x509FieldContainer = x509FieldContainer;
    }

    @Override
    public byte[] encode() {
        List<Asn1Encodable> children = this.x509FieldContainer.getFields();
        Asn1FieldContainer asn1FieldContainer = this.x509FieldContainer.getAsn1Field();
        asn1FieldContainer.clearChildren();
        asn1FieldContainer.addChildren(children);
        return super.encode();
    }
}
