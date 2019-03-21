package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.x509attacker.asn1.Asn1TagClass;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1Explicit extends Asn1Field {

    private static final String DEFAULT_EXPLICIT_TAG_CLASS = Asn1TagClass.CONTEXT_SPECIFIC.toString();
    private static final int DEFAULT_EXPLICIT_TAG_NUMBER = 0;

    @XmlElement
    private String asn1ExplicitTagClass = DEFAULT_EXPLICIT_TAG_CLASS;

    @XmlElement
    private int asn1ExplicitTagNumber = DEFAULT_EXPLICIT_TAG_NUMBER;

    @XmlElement
    private ModifiableString asn1ExplicitTagClassModification = new ModifiableString();

    @XmlElement
    private ModifiableInteger asn1ExplicitTagNumberModification = new ModifiableInteger();

    @XmlAnyElement(lax = true)
    private Asn1RawField explicitField = null;

    public Asn1Explicit() {
        super();
    }

    public ModifiableString getAsn1ExplicitTagClassModification() {
        return asn1ExplicitTagClassModification;
    }

    public void setAsn1ExplicitTagClassModification(ModifiableString asn1ExplicitTagClassModification) {
        this.asn1ExplicitTagClassModification = asn1ExplicitTagClassModification;
    }

    public ModifiableInteger getAsn1ExplicitTagNumberModification() {
        return asn1ExplicitTagNumberModification;
    }

    public void setAsn1ExplicitTagNumberModification(ModifiableInteger asn1ExplicitTagNumberModification) {
        this.asn1ExplicitTagNumberModification = asn1ExplicitTagNumberModification;
    }

    public Asn1RawField getExplicitField() {
        return explicitField;
    }

    public void setExplicitField(Asn1RawField explicitField) {
        this.explicitField = explicitField;
    }

    @Override
    protected void encodeForParentLayer() {
        this.updateDefaultValues();
        byte[] content = this.createContentBytes();
        super.setAsn1TagClass(Asn1TagClass.fromString(this.asn1ExplicitTagClassModification.getValue()).toString());
        super.setAsn1IsConstructed(true);
        super.setAsn1TagNumber(this.asn1ExplicitTagNumberModification.getValue());
        super.setAsn1Content(content);
        super.encodeForParentLayer();
    }

    private void updateDefaultValues() {
        if (this.asn1ExplicitTagClassModification.getOriginalValue() == null) {
            this.asn1ExplicitTagClassModification = ModifiableVariableFactory.safelySetValue(this.asn1ExplicitTagClassModification, this.asn1ExplicitTagClass);
        }
        if (this.asn1ExplicitTagNumberModification.getOriginalValue() == null) {
            this.asn1ExplicitTagNumberModification = ModifiableVariableFactory.safelySetValue(this.asn1ExplicitTagNumberModification, this.asn1ExplicitTagNumber);
        }
    }

    private byte[] createContentBytes() {
        byte[] contentBytes = null;
        if (this.explicitField != null) {
            contentBytes = this.explicitField.encode();
        } else {
            contentBytes = new byte[0];
        }
        return contentBytes;
    }
}
