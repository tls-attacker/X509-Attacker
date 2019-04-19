package de.rub.nds.asn1.encoder;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Explicit;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Asn1ExplicitEncoder extends Asn1FieldContainerEncoder {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Asn1Explicit asn1Explicit;

    public Asn1ExplicitEncoder(Asn1Explicit asn1Explicit) {
        super(asn1Explicit);
        this.asn1Explicit = asn1Explicit;
    }

    @Override
    public byte[] encode() {
        this.updateModifiableVariables();
        this.encodeExplicit();
        return super.encode();
    }

    private void updateModifiableVariables() {
        int offset = this.asn1Explicit.getOffset();
        this.asn1Explicit.setOffsetModificationValue(offset);
    }

    private void encodeExplicit() {
        this.asn1Explicit.setTagNumber(this.asn1Explicit.getFinalOffset());
    }
}
