package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagClass;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagNumber;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1Ia5String extends Asn1Field {

    @XmlElement
    private ModifiableString asn1Ia5StringValue;

    public Asn1Ia5String() {
        super();
        this.asn1Ia5StringValue = new ModifiableString();
    }

    public ModifiableString getAsn1Ia5StringValue() {
        return asn1Ia5StringValue;
    }

    public void setAsn1Ia5StringValue(ModifiableString asn1Ia5StringValue) {
        this.asn1Ia5StringValue = asn1Ia5StringValue;
    }

    public void setAsn1Ia5StringValue(String asn1Ia5StringValue) {
        this.asn1Ia5StringValue = ModifiableVariableFactory.safelySetValue(this.asn1Ia5StringValue, asn1Ia5StringValue);
    }

    @Override
    protected void encodeForParentLayer() {
        byte[] content = this.createContentBytes();
        super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
        super.setAsn1IsConstructed(false);
        super.setAsn1TagNumber(Asn1TagNumber.IA5STRING.getIntValue());
        super.setAsn1Content(content);
        super.encodeForParentLayer();
    }

    private byte[] createContentBytes() {
        byte[] contentBytes = null;
        if (this.asn1Ia5StringValue != null) {
            contentBytes = this.asn1Ia5StringValue.getValue().getBytes();
        }
        return contentBytes;
    }
}
