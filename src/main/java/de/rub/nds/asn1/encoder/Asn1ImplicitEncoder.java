package de.rub.nds.asn1.encoder;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.model.Asn1Implicit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Asn1ImplicitEncoder extends Asn1FieldEncoder {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Asn1Implicit asn1Implicit;

    public Asn1ImplicitEncoder(Asn1Implicit asn1Implicit) {
        super(asn1Implicit);
        this.asn1Implicit = asn1Implicit;
    }

    @Override
    public byte[] encode() {
        this.updateModifiableVariables();
        this.encodeImplicit();
        return super.encode();
    }

    private void updateModifiableVariables() {
        int implicitTagClass = this.asn1Implicit.getImplicitTagClass();
        int offset = this.asn1Implicit.getOffset();
        this.asn1Implicit.setImplicitTagClassModificationValue(implicitTagClass);
        this.asn1Implicit.setOffsetModificationValue(offset);
    }

    private void encodeImplicit() {
        byte[] content = new byte[] { };
        boolean isConstructed = false;
        Asn1Encodable implicitAsn1Field = this.asn1Implicit.getAsn1Encodable();
        if(implicitAsn1Field != null) {
            Asn1Field asn1Field = implicitAsn1Field.getEncoder().encodeAndGetAsn1Field();
            if(asn1Field != null) {
                content = asn1Field.getContent();
                isConstructed = asn1Field.isConstructed();
            }
        }
        this.asn1Implicit.setContent(content);
        this.asn1Implicit.setTagClass(this.asn1Implicit.getFinalTagClass());
        this.asn1Implicit.setConstructed(isConstructed);
        this.asn1Implicit.setTagNumber(this.asn1Implicit.getFinalOffset());
    }
}
