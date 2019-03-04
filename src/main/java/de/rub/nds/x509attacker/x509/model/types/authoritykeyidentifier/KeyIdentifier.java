package de.rub.nds.x509attacker.x509.model.types.authoritykeyidentifier;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.x509attacker.x509.model.x509asn1types.X509Asn1OctetString;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyIdentifier extends X509Asn1OctetString {

    @XmlElement
    private ModifiableByteArray value;

    public KeyIdentifier() {
        super();
        this.value = new ModifiableByteArray();
    }

    public ModifiableByteArray getValue() {
        return value;
    }

    public void setValue(ModifiableByteArray value) {
        this.value = value;
    }
}
