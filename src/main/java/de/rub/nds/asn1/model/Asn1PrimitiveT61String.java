package de.rub.nds.asn1.model;

import de.rub.nds.asn1.TagClass;
import de.rub.nds.asn1.TagNumber;
import de.rub.nds.asn1.encoder.Asn1PrimitiveT61StringEncoder;
import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public final class Asn1PrimitiveT61String extends Asn1Field {

    public static final int TAG_CLASS = TagClass.UNIVERSAL.getIntValue();
    public static final boolean IS_CONSTRUCTED = false;
    public static final int TAG_NUMBER = TagNumber.T61STRING.getIntValue();

    @XmlElement
    private String t61StringValue = "";

    @XmlElement
    private ModifiableString t61StringValueModification = new ModifiableString();

    public Asn1PrimitiveT61String() {
        super(TAG_CLASS, IS_CONSTRUCTED, TAG_NUMBER);
    }

    public String getT61StringValue() {
        return t61StringValue;
    }

    public void setT61StringValue(String t61StringValue) {
        this.t61StringValue = t61StringValue;
    }

    public ModifiableString getT61StringValueModification() {
        return t61StringValueModification;
    }

    public void setT61StringValueModification(ModifiableString t61StringValueModification) {
        this.t61StringValueModification = t61StringValueModification;
    }

    public void setT61StringValueModificationValue(String t61StringValue) {
        this.t61StringValueModification = ModifiableVariableFactory.safelySetValue(this.t61StringValueModification, t61StringValue);
    }

    public String getFinalT61StringValue() {
        return this.t61StringValueModification.getValue();
    }

    @Override
    public Asn1Encoder getEncoder() {
        return new Asn1PrimitiveT61StringEncoder(this);
    }
}
