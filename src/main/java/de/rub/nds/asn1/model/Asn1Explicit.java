package de.rub.nds.asn1.model;

import de.rub.nds.asn1.TagClass;
import de.rub.nds.asn1.encoder.Asn1ExplicitEncoder;
import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public final class Asn1Explicit extends Asn1FieldContainer {

    public static final int TAG_CLASS = TagClass.CONTEXT_SPECIFIC.getIntValue();
    public static final boolean IS_CONSTRUCTED = true;
    public static final int DEFAULT_TAG_OFFSET = 0;

    @XmlElement
    private int offset = DEFAULT_TAG_OFFSET;

    @XmlElement
    private ModifiableInteger offsetModification = new ModifiableInteger();

    public Asn1Explicit() {
        super(TAG_CLASS, IS_CONSTRUCTED, DEFAULT_TAG_OFFSET);
        this.setOffset(DEFAULT_TAG_OFFSET);
    }

    public int getOffset() {
        return offset;
    }

    public void setOffset(int offset) {
        this.offset = offset;
    }

    public ModifiableInteger getOffsetModification() {
        return offsetModification;
    }

    public void setOffsetModification(ModifiableInteger offsetModification) {
        this.offsetModification = offsetModification;
    }

    public void setOffsetModificationValue(int offset) {
        this.offsetModification = ModifiableVariableFactory.safelySetValue(this.offsetModification, offset);
    }

    public int getFinalOffset() {
        return this.offsetModification.getValue();
    }

    @Override
    public Asn1Encoder getEncoder() {
        return new Asn1ExplicitEncoder(this);
    }
}
