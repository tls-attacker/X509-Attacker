package de.rub.nds.asn1.model;

import de.rub.nds.asn1.TagClass;
import de.rub.nds.asn1.TagNumber;
import de.rub.nds.asn1.encoder.Asn1PrimitiveUtcTimeEncoder;
import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public final class Asn1PrimitiveUtcTime extends Asn1Field {

    public static final int TAG_CLASS = TagClass.UNIVERSAL.getIntValue();
    public static final boolean IS_CONSTRUCTED = false;
    public static final int TAG_NUMBER = TagNumber.UTCTIME.getIntValue();

    @XmlElement
    private String utcTimeValue = "";

    @XmlElement
    private ModifiableString utcTimeValueModification = new ModifiableString();

    public Asn1PrimitiveUtcTime() {
        super(TAG_CLASS, IS_CONSTRUCTED, TAG_NUMBER);
    }

    public String getUtcTimeValue() {
        return utcTimeValue;
    }

    public void setUtcTimeValue(String utcTimeValue) {
        this.utcTimeValue = utcTimeValue;
    }

    public ModifiableString getUtcTimeValueModification() {
        return utcTimeValueModification;
    }

    public void setUtcTimeValueModification(ModifiableString utcTimeValueModification) {
        this.utcTimeValueModification = utcTimeValueModification;
    }

    public void setUtcTimeValueModificationValue(String utcTimeValue) {
        this.utcTimeValueModification = ModifiableVariableFactory.safelySetValue(this.utcTimeValueModification, utcTimeValue);
    }

    public String getFinalUtcTimeValue() {
        return this.utcTimeValueModification.getValue();
    }

    @Override
    public Asn1Encoder getEncoder() {
        return new Asn1PrimitiveUtcTimeEncoder(this);
    }
}
