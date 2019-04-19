package de.rub.nds.asn1.model;

import de.rub.nds.asn1.TagClass;
import de.rub.nds.asn1.TagNumber;
import de.rub.nds.asn1.encoder.Asn1PrimitiveIa5StringEncoder;
import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public final class Asn1PrimitiveIa5String extends Asn1Field {

    public static final int TAG_CLASS = TagClass.UNIVERSAL.getIntValue();
    public static final boolean IS_CONSTRUCTED = false;
    public static final int TAG_NUMBER = TagNumber.IA5STRING.getIntValue();

    @XmlElement
    private String ia5StringValue = "";

    @XmlElement
    private ModifiableString ia5StringValueModification = new ModifiableString();

    public Asn1PrimitiveIa5String() {
        super(TAG_CLASS, IS_CONSTRUCTED, TAG_NUMBER);
    }

    public String getIa5StringValue() {
        return ia5StringValue;
    }

    public void setIa5StringValue(String ia5StringValue) {
        this.ia5StringValue = ia5StringValue;
    }

    public ModifiableString getIa5StringValueModification() {
        return ia5StringValueModification;
    }

    public void setIa5StringValueModification(ModifiableString ia5StringValueModification) {
        this.ia5StringValueModification = ia5StringValueModification;
    }

    public void setIa5StringValueModificationValue(String ia5StringValue) {
        this.ia5StringValueModification = ModifiableVariableFactory.safelySetValue(this.ia5StringValueModification, ia5StringValue);
    }

    public String getFinalIa5StringValue() {
        return this.ia5StringValueModification.getValue();
    }

    @Override
    public Asn1Encoder getEncoder() {
        return new Asn1PrimitiveIa5StringEncoder(this);
    }
}
