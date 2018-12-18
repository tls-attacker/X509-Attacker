package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagClass;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagNumber;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1OctetString extends Asn1Field {

    @XmlElement
    private ModifiableByteArray asn1OctetStringValue;

    public Asn1OctetString() {
        super();
        this.asn1OctetStringValue = new ModifiableByteArray();
    }

    public ModifiableByteArray getAsn1OctetStringValue() {
        return asn1OctetStringValue;
    }

    public void setAsn1OctetStringValue(ModifiableByteArray asn1OctetStringValue) {
        this.asn1OctetStringValue = asn1OctetStringValue;
    }

    public void setAsn1OctetStringValue(byte[] asn1OctetStringValue) {
        this.asn1OctetStringValue = ModifiableVariableFactory.safelySetValue(this.asn1OctetStringValue, asn1OctetStringValue);
    }

    @Override
    protected void encodeForParentLayer() {
        byte[] content = this.createContentBytes();
        super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
        super.setAsn1IsConstructed(false);
        super.setAsn1TagNumber(Asn1TagNumber.OCTET_STRING.getIntValue());
        super.setAsn1Content(content);
        super.encodeForParentLayer();
    }

    private byte[] createContentBytes() {
        return this.asn1OctetStringValue.getValue();
    }
}
