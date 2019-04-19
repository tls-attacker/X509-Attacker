package de.rub.nds.asn1.model;

import de.rub.nds.asn1.TagClass;
import de.rub.nds.asn1.TagNumber;
import de.rub.nds.asn1.encoder.Asn1ObjectIdentifierEncoder;
import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public final class Asn1ObjectIdentifier extends Asn1Field {

    public static final int TAG_CLASS = TagClass.UNIVERSAL.getIntValue();
    public static final boolean IS_CONSTRUCTED = false;
    public static final int TAG_NUMBER = TagNumber.OBJECT_IDENTIFIER.getIntValue();

    @XmlElement
    private String objectIdentifierValue = "";

    @XmlElement
    private ModifiableString objectIdentifierValueModification = new ModifiableString();

    public Asn1ObjectIdentifier() {
        super(TAG_CLASS, IS_CONSTRUCTED, TAG_NUMBER);
    }

    public String getObjectIdentifierValue() {
        return objectIdentifierValue;
    }

    public void setObjectIdentifierValue(String objectIdentifierValue) {
        this.objectIdentifierValue = objectIdentifierValue;
    }

    public ModifiableString getObjectIdentifierValueModification() {
        return objectIdentifierValueModification;
    }

    public void setObjectIdentifierValueModification(ModifiableString objectIdentifierValueModification) {
        this.objectIdentifierValueModification = objectIdentifierValueModification;
    }

    public void setObjectIdentifierValueModificationValue(String objectIdentifierValue) {
        this.objectIdentifierValueModification = ModifiableVariableFactory.safelySetValue(this.objectIdentifierValueModification, objectIdentifierValue);
    }

    public String getFinalObjectIdentifierValue() {
        return this.objectIdentifierValueModification.getValue();
    }

    @Override
    public Asn1Encoder getEncoder() {
        return new Asn1ObjectIdentifierEncoder(this);
    }
}
