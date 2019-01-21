package de.rub.nds.x509attacker.x509.model.types.authoritykeyidentifier;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.x509attacker.x509.model.asn1types.Asn1OctetStringValueHolder;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyIdentifier extends Asn1OctetStringValueHolder {

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
