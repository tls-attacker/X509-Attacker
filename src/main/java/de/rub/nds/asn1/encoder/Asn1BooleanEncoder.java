package de.rub.nds.asn1.encoder;

import de.rub.nds.asn1.model.Asn1Boolean;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Asn1BooleanEncoder extends Asn1FieldEncoder {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Asn1Boolean asn1Boolean;

    public Asn1BooleanEncoder(Asn1Boolean asn1Boolean) {
        super(asn1Boolean);
        this.asn1Boolean = asn1Boolean;
    }

    @Override
    public byte[] encode() {
        this.updateModifiableVariables();
        this.encodeBoolean();
        return super.encode();
    }

    private void updateModifiableVariables() {
        boolean booleanValue = this.asn1Boolean.isBooleanValue();
        this.asn1Boolean.setBoolModificationValue(booleanValue);
    }

    private void encodeBoolean() {
        byte[] content = new byte[] { 0 };
        if(asn1Boolean.getFinalBooleanValue()) {
            content[0] = (byte) 0xFF;
        }
        this.asn1Boolean.setContent(content);
    }
}
