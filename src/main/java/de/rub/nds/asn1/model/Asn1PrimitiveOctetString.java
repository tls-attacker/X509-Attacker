package de.rub.nds.asn1.model;

import de.rub.nds.asn1.TagClass;
import de.rub.nds.asn1.TagNumber;
import de.rub.nds.asn1.encoder.Asn1PrimitiveOctetStringEncoder;
import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ByteArrayAdapter;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public final class Asn1PrimitiveOctetString extends Asn1Field {

    public static final int TAG_CLASS = TagClass.UNIVERSAL.getIntValue();
    public static final boolean IS_CONSTRUCTED = false;
    public static final int TAG_NUMBER = TagNumber.OCTET_STRING.getIntValue();

    @XmlElement
    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] octetStringValue = new byte[0];

    @XmlElement
    private ModifiableByteArray octetStringValueModification = new ModifiableByteArray();

    public Asn1PrimitiveOctetString() {
        super(TAG_CLASS, IS_CONSTRUCTED, TAG_NUMBER);
    }

    public byte[] getOctetStringValue() {
        return octetStringValue;
    }

    public void setOctetStringValue(byte[] octetStringValue) {
        this.octetStringValue = octetStringValue;
    }

    public ModifiableByteArray getOctetStringValueModification() {
        return octetStringValueModification;
    }

    public void setOctetStringValueModification(ModifiableByteArray octetStringValueModification) {
        this.octetStringValueModification = octetStringValueModification;
    }

    public void setOctetStringValueModificationValue(byte[] octetStringValue) {
        this.octetStringValueModification = ModifiableVariableFactory.safelySetValue(this.octetStringValueModification, octetStringValue);
    }

    public byte[] getFinalOctetStringValue() {
        return this.octetStringValueModification.getValue();
    }

    @Override
    public Asn1Encoder getEncoder() {
        return new Asn1PrimitiveOctetStringEncoder(this);
    }
}
