package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagClass;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1Explicit extends Asn1Field {

    @XmlElement
    private ModifiableString asn1ExplicitTagClass;

    @XmlElement
    private ModifiableInteger asn1ExplicitTagNumber;

    @XmlAnyElement
    private Asn1RawField explicitField = null;

    public Asn1Explicit() {
        super();
        this.asn1ExplicitTagClass = new ModifiableString();
        this.asn1ExplicitTagClass.setOriginalValue(Asn1TagClass.UNIVERSAL.toString());
        this.asn1ExplicitTagNumber = new ModifiableInteger();
        this.asn1ExplicitTagNumber.setOriginalValue(0);
    }

    public ModifiableString getAsn1ExplicitTagClass() {
        return asn1ExplicitTagClass;
    }

    public void setAsn1ExplicitTagClass(ModifiableString asn1ExplicitTagClass) {
        this.asn1ExplicitTagClass = asn1ExplicitTagClass;
    }

    public ModifiableInteger getAsn1ExplicitTagNumber() {
        return asn1ExplicitTagNumber;
    }

    public void setAsn1ExplicitTagNumber(ModifiableInteger asn1ExplicitTagNumber) {
        this.asn1ExplicitTagNumber = asn1ExplicitTagNumber;
    }

    public Asn1RawField getExplicitField() {
        return explicitField;
    }

    public void setExplicitField(Asn1RawField explicitField) {
        this.explicitField = explicitField;
    }

    @Override
    protected void encodeForParentLayer() {
        byte[] content = this.createContentBytes();
        super.setAsn1TagClass(Asn1TagClass.fromString(this.asn1ExplicitTagClass.getValue()).toString());
        super.setAsn1IsConstructed(true);
        super.setAsn1TagNumber(this.asn1ExplicitTagNumber.getValue());
        super.setAsn1Content(content);
        super.encodeForParentLayer();
    }

    private byte[] createContentBytes() {
        byte[] contentBytes = null;
        if (this.explicitField != null) {
            contentBytes = this.explicitField.encode();
        }
        return contentBytes;
    }
}
