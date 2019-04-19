package de.rub.nds.asn1.model;

import de.rub.nds.asn1.TagClass;
import de.rub.nds.asn1.TagNumber;
import de.rub.nds.asn1.encoder.Asn1PrimitiveUtf8StringEncoder;
import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public final class Asn1PrimitiveUtf8String extends Asn1Field {

    public static final int TAG_CLASS = TagClass.UNIVERSAL.getIntValue();
    public static final boolean IS_CONSTRUCTED = false;
    public static final int TAG_NUMBER = TagNumber.UTF8STRING.getIntValue();

    @XmlElement
    private String utf8StringValue = "";

    @XmlElement
    private ModifiableString utf8StringValueModification = new ModifiableString();

    public Asn1PrimitiveUtf8String() {
        super(TAG_CLASS, IS_CONSTRUCTED, TAG_NUMBER);
    }

    public String getUtf8StringValue() {
        return utf8StringValue;
    }

    public void setUtf8StringValue(String utf8StringValue) {
        this.utf8StringValue = utf8StringValue;
    }

    public ModifiableString getUtf8StringValueModification() {
        return utf8StringValueModification;
    }

    public void setUtf8StringValueModification(ModifiableString utf8StringValueModification) {
        this.utf8StringValueModification = utf8StringValueModification;
    }

    public void setUtf8StringValueModificationValue(String utf8StringValue) {
        this.utf8StringValueModification = ModifiableVariableFactory.safelySetValue(this.utf8StringValueModification, utf8StringValue);
    }

    public String getFinalUtf8StringValue() {
        return this.utf8StringValueModification.getValue();
    }

    @Override
    public Asn1Encoder getEncoder() {
        return new Asn1PrimitiveUtf8StringEncoder(this);
    }
}
