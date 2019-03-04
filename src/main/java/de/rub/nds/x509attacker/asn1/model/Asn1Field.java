package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagClass;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class Asn1Field extends Asn1AbstractField {

    @XmlElement
    private ModifiableString asn1TagClass;

    @XmlElement
    private ModifiableBoolean asn1IsConstructed;

    @XmlElement
    private ModifiableInteger asn1TagNumber;

    @XmlElement
    private ModifiableInteger asn1Length;

    @XmlElement
    ModifiableByteArray asn1Content;

    protected Asn1Field() {
        super();
        this.asn1TagClass = new ModifiableString();
        this.asn1IsConstructed = new ModifiableBoolean();
        this.asn1TagNumber = new ModifiableInteger();
        this.asn1Length = new ModifiableInteger();
        this.asn1Content = new ModifiableByteArray();
    }

    public ModifiableString getAsn1TagClass() {
        return asn1TagClass;
    }

    public void setAsn1TagClass(ModifiableString asn1TagClass) {
        this.asn1TagClass = asn1TagClass;
    }

    public void setAsn1TagClass(String asn1TagClass) {
        this.asn1TagClass = ModifiableVariableFactory.safelySetValue(this.asn1TagClass, asn1TagClass);
    }

    public ModifiableBoolean getAsn1IsConstructed() {
        return asn1IsConstructed;
    }

    public void setAsn1IsConstructed(ModifiableBoolean asn1IsConstructed) {
        this.asn1IsConstructed = asn1IsConstructed;
    }

    public void setAsn1IsConstructed(boolean isConstructed) {
        this.asn1IsConstructed = ModifiableVariableFactory.safelySetValue(this.asn1IsConstructed, isConstructed);
    }

    public ModifiableInteger getAsn1TagNumber() {
        return asn1TagNumber;
    }

    public void setAsn1TagNumber(ModifiableInteger asn1TagNumber) {
        this.asn1TagNumber = asn1TagNumber;
    }

    public void setAsn1TagNumber(int asn1TagNumber) {
        this.asn1TagNumber = ModifiableVariableFactory.safelySetValue(this.asn1TagNumber, asn1TagNumber);
    }

    public ModifiableInteger getAsn1Length() {
        return asn1Length;
    }

    public void setAsn1Length(ModifiableInteger asn1Length) {
        this.asn1Length = asn1Length;
    }

    public void setAsn1Length(int asn1Length) {
        this.asn1Length = ModifiableVariableFactory.safelySetValue(this.asn1Length, asn1Length);
    }

    public ModifiableByteArray getAsn1Content() {
        return asn1Content;
    }

    public void setAsn1Content(ModifiableByteArray asn1Content) {
        this.asn1Content = asn1Content;
    }

    public void setAsn1Content(byte[] asn1Content) {
        this.asn1Content = ModifiableVariableFactory.safelySetValue(this.asn1Content, asn1Content);
    }

    @Override
    protected void encodeForParentLayer() {
        byte[] rawIdentifier = this.createRawIdentifierBytes();
        byte[] rawContent = this.createRawContentBytes();
        byte[] rawLength = this.createRawLengthBytes(rawContent);
        super.setAsn1RawIdentifier(rawIdentifier);
        super.setAsn1RawLength(rawLength);
        super.setAsn1RawContent(rawContent);
        super.encodeForParentLayer();
    }

    private byte[] createRawIdentifierBytes() {
        int tagClass = Asn1TagClass.fromString(this.asn1TagClass.getValue()).getIntValue();
        boolean isConstructed = this.asn1IsConstructed.getValue();
        int tagNumber = this.asn1TagNumber.getValue();
        byte[] tagNumberBytes = this.createTagNumberBytes(tagNumber);
        return this.mergeIdentifierValues(tagClass, isConstructed, tagNumberBytes);
    }

    private byte[] createTagNumberBytes(int tagNumber) {
        byte[] tagNumberBytes = null;
        if (tagNumber < 0) {
            throw new RuntimeException("Tag number can never be negative!");
        } else if (tagNumber <= 30) {
            tagNumberBytes = new byte[1];
            tagNumberBytes[0] = (byte) tagNumber;
        } else {
            byte additionalBytesFlag = 0;
            int requiredBytes = this.computeNumberOfAdditionalBytesForTagNumber(tagNumber);
            tagNumberBytes = new byte[1 + requiredBytes]; // One additional byte for prefix 0x1F, i.e. the indicator that the tag number is encoded in multiple bytes.
            tagNumberBytes[0] = 0x1F;
            for (int i = requiredBytes; i > 0; i--) {
                tagNumberBytes[i] = (byte) ((tagNumber & 0x7F) | additionalBytesFlag);
                tagNumber = tagNumber >> 7;
                additionalBytesFlag = (byte) 0x80;
            }
        }
        return tagNumberBytes;
    }

    private int computeNumberOfAdditionalBytesForTagNumber(int tagNumber) {
        int bytesRequired = 0;
        if (tagNumber > 30) {
            while (tagNumber > 0) {
                bytesRequired++;
                tagNumber = tagNumber >> 7;
            }
        }
        return bytesRequired;
    }

    private byte[] mergeIdentifierValues(int tagClass, boolean isConstructed, byte[] prefixedTagNumberBytes) {
        byte[] rawIdentifierBytes = prefixedTagNumberBytes.clone();
        rawIdentifierBytes[0] &= 0x1F; // First byte of tag number MUST use the five least significant bits only.
        rawIdentifierBytes[0] |= (tagClass & 0x03) << 6;
        rawIdentifierBytes[0] |= isConstructed ? 0x20 : 0x00;
        return rawIdentifierBytes;
    }

    private byte[] createRawLengthBytes(byte[] rawContentBytes) {
        byte[] rawLengthBytes = null;
        this.asn1Length.setOriginalValue(rawContentBytes.length);
        int length = this.asn1Length.getValue();
        if (length < 0) {
            length = 0;
        }
        if (length >= 0 && length <= 127) {
            rawLengthBytes = new byte[]{(byte) length};
        } else {
            int numberOfLengthBytes = this.computeNumberOfLengthBytes(length);
            rawLengthBytes = new byte[1 + numberOfLengthBytes];
            rawContentBytes[0] = (byte) 0x80;
            for (int i = numberOfLengthBytes; i > 0; i--) {
                rawLengthBytes[i] = (byte) (length & 0xFF);
                length = length >> 8;
            }
        }
        return rawLengthBytes;
    }

    private int computeNumberOfLengthBytes(int length) {
        int bytesRequired = 0;
        while (length > 0) {
            bytesRequired++;
            length = length >> 8;
        }
        return bytesRequired;
    }

    private byte[] createRawContentBytes() {
        return this.asn1Content.getValue();
    }
}
