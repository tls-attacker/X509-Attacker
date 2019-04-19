package de.rub.nds.asn1.model;

import de.rub.nds.asn1.TagClass;
import de.rub.nds.asn1.TagNumber;
import de.rub.nds.asn1.encoder.Asn1BooleanEncoder;
import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public final class Asn1Boolean extends Asn1Field {

    public static final int TAG_CLASS = TagClass.UNIVERSAL.getIntValue();
    public static final boolean IS_CONSTRUCTED = false;
    public static final int TAG_NUMBER = TagNumber.BOOLEAN.getIntValue();

    @XmlElement
    private boolean booleanValue = false;

    @XmlElement
    private ModifiableBoolean boolModification = new ModifiableBoolean();

    public Asn1Boolean() {
        super(TAG_CLASS, IS_CONSTRUCTED, TAG_NUMBER);
    }

    public boolean isBooleanValue() {
        return booleanValue;
    }

    public void setBooleanValue(boolean booleanValue) {
        this.booleanValue = booleanValue;
    }

    public ModifiableBoolean getBoolModification() {
        return boolModification;
    }

    public void setBoolModification(ModifiableBoolean boolModification) {
        this.boolModification = boolModification;
    }

    public void setBoolModificationValue(boolean booleanValue) {
        this.boolModification = ModifiableVariableFactory.safelySetValue(this.boolModification, booleanValue);
    }

    public boolean getFinalBooleanValue() {
        return this.boolModification.getValue();
    }

    @Override
    public Asn1Encoder getEncoder() {
        return new Asn1BooleanEncoder(this);
    }
}
