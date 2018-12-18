package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;

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
}
