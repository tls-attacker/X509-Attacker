package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlTransient;

@XmlTransient
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class Asn1RawField {

    @XmlTransient
    private boolean isEncodeForParentLayerCalled = false;

    @XmlElement
    private ModifiableByteArray asn1RawFieldContent;

    protected Asn1RawField() {
        this.asn1RawFieldContent = new ModifiableByteArray();
    }

    public ModifiableByteArray getAsn1RawFieldContent() {
        return asn1RawFieldContent;
    }

    public void setAsn1RawFieldContent(ModifiableByteArray asn1RawFieldContent) {
        this.asn1RawFieldContent = asn1RawFieldContent;
    }

    public void setAsn1RawFieldContent(byte[] asn1RawContent) {
        this.asn1RawFieldContent = ModifiableVariableFactory.safelySetValue(this.asn1RawFieldContent, asn1RawContent);
    }

    /**
     * Implementation of abstract encode method of Asn1Encoder. Calls encodeForParentLayer before computing the
     * contents to ensure that all deriving classes write their data to the parent layers.
     *
     * @return The encoded data as a byte array.
     */
    public byte[] encode() {
        byte[] encodedValue;
        if (this.isEncodeForParentLayerCalled == false) {
            this.encodeForParentLayer();
        }
        if (this.isEncodeForParentLayerCalled) {
            encodedValue = this.asn1RawFieldContent.getValue();
        } else {
            throw new RuntimeException("Asn1RawFieldEncoder.encodeForParentLayer() not executed! Did you call super.encodeForParentLayer() in all overriding methods?");
        }
        return encodedValue;
    }

    /**
     * Called by encode to ensure that deriving classes write their data to the parent layers (and hence, eventually,
     * the data will be written to Asn1RawField's asn1RawFieldContent). MUST call super.encodeForParentLayer() to ensure
     * correct propagation of data across multiple layers.
     */
    protected void encodeForParentLayer() {
        this.isEncodeForParentLayerCalled = true;
    }
}
