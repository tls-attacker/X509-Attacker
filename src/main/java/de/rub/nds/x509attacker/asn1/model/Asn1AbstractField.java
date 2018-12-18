package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlTransient;
import java.nio.ByteBuffer;

@XmlTransient
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class Asn1AbstractField extends Asn1RawField {

    @XmlElement
    private ModifiableByteArray asn1RawIdentifier;

    @XmlElement
    private ModifiableByteArray asn1RawLength;

    @XmlElement
    private ModifiableByteArray asn1RawContent;

    protected Asn1AbstractField() {
        this.asn1RawIdentifier = new ModifiableByteArray();
        this.asn1RawLength = new ModifiableByteArray();
        this.asn1RawContent = new ModifiableByteArray();
    }

    public ModifiableByteArray getAsn1RawIdentifier() {
        return asn1RawIdentifier;
    }

    public void setAsn1RawIdentifier(ModifiableByteArray asn1RawIdentifier) {
        this.asn1RawIdentifier = asn1RawIdentifier;
    }

    public void setAsn1RawIdentifier(byte[] asn1RawIdentifier) {
        this.asn1RawIdentifier = ModifiableVariableFactory.safelySetValue(this.asn1RawIdentifier, asn1RawIdentifier);
    }

    public ModifiableByteArray getAsn1RawLength() {
        return asn1RawLength;
    }

    public void setAsn1RawLength(ModifiableByteArray asn1RawLength) {
        this.asn1RawLength = asn1RawLength;
    }

    public void setAsn1RawLength(byte[] asn1RawLength) {
        this.asn1RawLength = ModifiableVariableFactory.safelySetValue(this.asn1RawLength, asn1RawLength);
    }

    public ModifiableByteArray getAsn1RawContent() {
        return asn1RawContent;
    }

    public void setAsn1RawContent(ModifiableByteArray asn1RawContent) {
        this.asn1RawContent = asn1RawContent;
    }

    public void setAsn1RawContent(byte[] asn1RawContent) {
        this.asn1RawContent = ModifiableVariableFactory.safelySetValue(this.asn1RawContent, asn1RawContent);
    }

    @Override
    protected void encodeForParentLayer() {
        byte[] rawFieldContent = this.createRawFieldBytes();
        super.setAsn1RawFieldContent(rawFieldContent);
        super.encodeForParentLayer();
    }

    private byte[] createRawFieldBytes() {
        byte[] rawIdentifier = this.asn1RawIdentifier.getValue();
        byte[] rawLength = this.asn1RawLength.getValue();
        byte[] rawContent = this.asn1RawContent.getValue();
        ByteBuffer rawFieldContentBuffer = ByteBuffer.allocate(rawIdentifier.length + rawLength.length + rawContent.length);
        rawFieldContentBuffer.put(rawIdentifier);
        rawFieldContentBuffer.put(rawLength);
        rawFieldContentBuffer.put(rawContent);
        return rawFieldContentBuffer.array();
    }
}
