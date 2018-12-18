package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagClass;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagNumber;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1T61String extends Asn1Field {

    @XmlElement
    private ModifiableString asn1T61StringValue;

    public Asn1T61String() {
        super();
        this.asn1T61StringValue = new ModifiableString();
    }

    public ModifiableString getAsn1T61StringValue() {
        return asn1T61StringValue;
    }

    public void setAsn1T61StringValue(ModifiableString asn1T61StringValue) {
        this.asn1T61StringValue = asn1T61StringValue;
    }

    public void setAsn1T61StringValue(String asn1T61StringValue) {
        this.asn1T61StringValue = ModifiableVariableFactory.safelySetValue(this.asn1T61StringValue, asn1T61StringValue);
    }

    @Override
    protected void encodeForParentLayer() {
        byte[] content = this.createContentBytes();
        super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
        super.setAsn1IsConstructed(false);
        super.setAsn1TagNumber(Asn1TagNumber.T61STRING.getIntValue());
        super.setAsn1Content(content);
        super.encodeForParentLayer();
    }

    private byte[] createContentBytes() {
        byte[] contentBytes = null;
        if (this.asn1T61StringValue != null) {
            contentBytes = this.asn1T61StringValue.getValue().getBytes();
        }
        return contentBytes;
    }
}
