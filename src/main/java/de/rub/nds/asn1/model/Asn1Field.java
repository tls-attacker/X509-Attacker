package de.rub.nds.asn1.model;

import de.rub.nds.asn1.encoder.Asn1FieldEncoder;
import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.filter.ModificationFilterFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.math.BigInteger;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1Field extends Asn1Encodable {

    @XmlElement
    private int tagClass = 0;

    @XmlElement
    private ModifiableInteger tagClassModification = new ModifiableInteger();

    @XmlElement
    private boolean isConstructed = false;

    @XmlElement
    private ModifiableBoolean isConstructedModification = new ModifiableBoolean();

    @XmlElement
    private int tagNumber = 0;

    @XmlElement
    private ModifiableInteger tagNumberModification = new ModifiableInteger();

    @XmlElement
    private BigInteger length = BigInteger.ZERO;

    @XmlElement
    private ModifiableBigInteger lengthModification = new ModifiableBigInteger();

    @XmlElement
    private byte[] content = new byte[0];

    @XmlElement
    private ModifiableByteArray contentModification = new ModifiableByteArray();

    public Asn1Field() {
        super();
    }

    public Asn1Field(int tagClass, boolean isConstructed, int tagNumber) {
        super();
        this.setTagClass(tagClass);
        this.setConstructed(isConstructed);
        this.setTagNumber(tagNumber);
    }

    public int getTagClass() {
        return tagClass;
    }

    public void setTagClass(int tagClass) {
        this.tagClass = tagClass;
    }

    public ModifiableInteger getTagClassModification() {
        return tagClassModification;
    }

    public void setTagClassModification(ModifiableInteger tagClassModification) {
        this.tagClassModification = tagClassModification;
    }

    public void setTagClassModificationValue(int tagClass) {
        this.tagClassModification = ModifiableVariableFactory.safelySetValue(this.tagClassModification, tagClass);
    }

    public int getFinalTagClass() {
        return this.tagClassModification.getValue();
    }

    public boolean isConstructed() {
        return isConstructed;
    }

    public void setConstructed(boolean constructed) {
        isConstructed = constructed;
    }

    public ModifiableBoolean getIsConstructedModification() {
        return isConstructedModification;
    }

    public void setIsConstructedModification(ModifiableBoolean isConstructedModification) {
        this.isConstructedModification = isConstructedModification;
    }

    public void setIsConstructedModificationValue(boolean isConstructed) {
        this.isConstructedModification = ModifiableVariableFactory.safelySetValue(this.isConstructedModification, isConstructed);
    }

    public boolean getFinalIsConstructed() {
        return this.isConstructedModification.getValue();
    }

    public int getTagNumber() {
        return tagNumber;
    }

    public void setTagNumber(int tagNumber) {
        this.tagNumber = tagNumber;
    }

    public ModifiableInteger getTagNumberModification() {
        return tagNumberModification;
    }

    public void setTagNumberModification(ModifiableInteger tagNumberModification) {
        this.tagNumberModification = tagNumberModification;
    }

    public void setTagNumberModificationValue(int tagNumber) {
        this.tagNumberModification = ModifiableVariableFactory.safelySetValue(this.tagNumberModification, tagNumber);
    }

    public int getFinalTagNumber() {
        return this.tagNumberModification.getValue();
    }

    public BigInteger getLength() {
        return length;
    }

    public void setLength(BigInteger length) {
        this.length = length;
    }

    public ModifiableBigInteger getLengthModification() {
        return lengthModification;
    }

    public void setLengthModification(ModifiableBigInteger lengthModification) {
        this.lengthModification = lengthModification;
    }

    public void setLengthModificationValue(BigInteger length) {
        this.lengthModification = ModifiableVariableFactory.safelySetValue(this.lengthModification, length);
    }

    public BigInteger getFinalLength() {
        return this.lengthModification.getValue();
    }

    public byte[] getContent() {
        return content;
    }

    public void setContent(byte[] content) {
        this.content = content;
    }

    public ModifiableByteArray getContentModification() {
        return contentModification;
    }

    public void setContentModification(ModifiableByteArray contentModification) {
        this.contentModification = contentModification;
    }

    public void setContentModificationValue(byte[] content) {
        this.contentModification = ModifiableVariableFactory.safelySetValue(this.contentModification, content);
    }

    public byte[] getFinalContent() {
        return this.contentModification.getValue();
    }

    @Override
    public Asn1Encoder getEncoder() {
        return new Asn1FieldEncoder(this);
    }

    @Override
    public Asn1Field getAsn1Field() {
        return this;
    }
}
