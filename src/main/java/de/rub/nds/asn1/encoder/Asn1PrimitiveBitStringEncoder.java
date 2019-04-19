package de.rub.nds.asn1.encoder;

import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Asn1PrimitiveBitStringEncoder extends Asn1FieldEncoder {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Asn1PrimitiveBitString asn1PrimitiveBitString;

    public Asn1PrimitiveBitStringEncoder(Asn1PrimitiveBitString asn1PrimitiveBitString) {
        super(asn1PrimitiveBitString);
        this.asn1PrimitiveBitString = asn1PrimitiveBitString;
    }

    @Override
    public byte[] encode() {
        this.updateModifiableVariables();
        this.encodePrimitiveBitString();
        return super.encode();
    }

    private void updateModifiableVariables() {
        int unusedBits = this.asn1PrimitiveBitString.getUnusedBits();
        byte[] bitStringValue = this.asn1PrimitiveBitString.getBitStringValue();
        this.asn1PrimitiveBitString.setUnusedBitsModificationValue(unusedBits);
        this.asn1PrimitiveBitString.setBitStringValueModificationValue(bitStringValue);
    }

    private void encodePrimitiveBitString() {
        byte[] content = new byte[] { (byte) this.asn1PrimitiveBitString.getFinalUnusedBits() };
        content = merge(content, this.asn1PrimitiveBitString.getFinalBitStringValue());
        this.asn1PrimitiveBitString.setContent(content);
    }
}
