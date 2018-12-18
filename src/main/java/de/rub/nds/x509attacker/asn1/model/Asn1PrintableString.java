package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagClass;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagNumber;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1PrintableString extends Asn1Field {

    @XmlElement
    private ModifiableString asn1PrintableStringValue;

    public Asn1PrintableString() {
        super();
        this.asn1PrintableStringValue = new ModifiableString();
    }

    public ModifiableString getAsn1PrintableStringValue() {
        return asn1PrintableStringValue;
    }

    public void setAsn1PrintableStringValue(ModifiableString asn1PrintableStringValue) {
        this.asn1PrintableStringValue = asn1PrintableStringValue;
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
        if (this.asn1PrintableStringValue != null) {
            contentBytes = this.asn1PrintableStringValue.getValue().getBytes();
        }
        return contentBytes;
    }
}
