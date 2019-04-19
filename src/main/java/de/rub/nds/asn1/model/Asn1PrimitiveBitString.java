package de.rub.nds.asn1.model;

import de.rub.nds.asn1.TagClass;
import de.rub.nds.asn1.TagNumber;
import de.rub.nds.asn1.encoder.Asn1PrimitiveBitStringEncoder;
import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.util.ByteArrayAdapter;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public final class Asn1PrimitiveBitString extends Asn1Field {

    public static final int TAG_CLASS = TagClass.UNIVERSAL.getIntValue();
    public static final boolean IS_CONSTRUCTED = false;
    public static final int TAG_NUMBER = TagNumber.BIT_STRING.getIntValue();

    @XmlElement
    private int unusedBits = 0;

    @XmlElement
    private ModifiableInteger unusedBitsModification = new ModifiableInteger();

    @XmlElement
    @XmlJavaTypeAdapter(ByteArrayAdapter.class)
    private byte[] bitStringValue = new byte[0];

    @XmlElement
    private ModifiableByteArray bitStringValueModification = new ModifiableByteArray();

    public Asn1PrimitiveBitString() {
        super(TAG_CLASS, IS_CONSTRUCTED, TAG_NUMBER);
    }

    public int getUnusedBits() {
        return unusedBits;
    }

    public void setUnusedBits(int unusedBits) {
        this.unusedBits = unusedBits;
    }

    public ModifiableInteger getUnusedBitsModification() {
        return unusedBitsModification;
    }

    public void setUnusedBitsModification(ModifiableInteger unusedBitsModification) {
        this.unusedBitsModification = unusedBitsModification;
    }

    public void setUnusedBitsModificationValue(int unusedBits) {
        this.unusedBitsModification = ModifiableVariableFactory.safelySetValue(this.unusedBitsModification, unusedBits);
    }

    public int getFinalUnusedBits() {
        return this.unusedBitsModification.getValue();
    }

    public byte[] getBitStringValue() {
        return bitStringValue;
    }

    public void setBitStringValue(byte[] bitStringValue) {
        this.bitStringValue = bitStringValue;
    }

    public ModifiableByteArray getBitStringValueModification() {
        return bitStringValueModification;
    }

    public void setBitStringValueModification(ModifiableByteArray bitStringValueModification) {
        this.bitStringValueModification = bitStringValueModification;
    }

    public void setBitStringValueModificationValue(byte[] bitStringValue) {
        this.bitStringValueModification = ModifiableVariableFactory.safelySetValue(this.bitStringValueModification, bitStringValue);
    }

    public byte[] getFinalBitStringValue() {
        return this.bitStringValueModification.getValue();
    }

    @Override
    public Asn1Encoder getEncoder() {
        return new Asn1PrimitiveBitStringEncoder(this);
    }
}
