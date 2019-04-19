package de.rub.nds.asn1.model;

import de.rub.nds.asn1.TagClass;
import de.rub.nds.asn1.encoder.Asn1ImplicitEncoder;
import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public final class Asn1Implicit extends Asn1Field {

    public static final int DEFAULT_TAG_CLASS = TagClass.CONTEXT_SPECIFIC.getIntValue();
    public static final int DEFAULT_TAG_OFFSET = 0;

    @XmlElement
    private int implicitTagClass = DEFAULT_TAG_CLASS;

    @XmlElement
    private ModifiableInteger implicitTagClassModification = new ModifiableInteger();

    @XmlElement
    private int offset = DEFAULT_TAG_OFFSET;

    @XmlElement
    private ModifiableInteger offsetModification = new ModifiableInteger();

    @XmlAnyElement(lax = true)
    private Asn1Encodable asn1Encodable = null;

    public Asn1Implicit() {
        super(DEFAULT_TAG_CLASS, false, DEFAULT_TAG_OFFSET);
    }

    public int getImplicitTagClass() {
        return implicitTagClass;
    }

    public void setImplicitTagClass(int implicitTagClass) {
        this.implicitTagClass = implicitTagClass;
    }

    public ModifiableInteger getImplicitTagClassModification() {
        return implicitTagClassModification;
    }

    public void setImplicitTagClassModification(ModifiableInteger implicitTagClassModification) {
        this.implicitTagClassModification = implicitTagClassModification;
    }

    public void setImplicitTagClassModificationValue(int implicitTagClass) {
        this.implicitTagClassModification = ModifiableVariableFactory.safelySetValue(this.implicitTagClassModification, implicitTagClass);
    }

    public int getFinalTagClass() {
        return this.implicitTagClassModification.getValue();
    }

    public int getOffset() {
        return offset;
    }

    public void setOffset(int offset) {
        this.offset = offset;
    }

    public ModifiableInteger getOffsetModification() {
        return offsetModification;
    }

    public void setOffsetModification(ModifiableInteger offsetModification) {
        this.offsetModification = offsetModification;
    }

    public void setOffsetModificationValue(int offset) {
        this.offsetModification = ModifiableVariableFactory.safelySetValue(this.offsetModification, offset);
    }

    public int getFinalOffset() {
        return this.offsetModification.getValue();
    }

    public Asn1Encodable getAsn1Encodable() {
        return asn1Encodable;
    }

    public void setAsn1Encodable(Asn1Encodable asn1Encodable) {
        this.asn1Encodable = asn1Encodable;
    }

    @Override
    public Asn1Encoder getEncoder() {
        return new Asn1ImplicitEncoder(this);
    }
}
