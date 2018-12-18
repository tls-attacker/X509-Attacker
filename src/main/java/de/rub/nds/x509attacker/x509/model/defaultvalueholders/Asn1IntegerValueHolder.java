package de.rub.nds.x509attacker.x509.model.defaultvalueholders;

import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.x509attacker.asn1.model.Asn1Integer;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1IntegerValueHolder extends Asn1Integer {

    @XmlAttribute
    private boolean excludeFromSignature = false;

    @XmlAttribute
    private boolean excludeFromCertificate = false;

    @XmlElement
    private ModifiableInteger value;

    public Asn1IntegerValueHolder() {
        super();
        this.value = new ModifiableInteger();
    }

    public boolean isExcludeFromSignature() {
        return excludeFromSignature;
    }

    public void setExcludeFromSignature(boolean excludeFromSignature) {
        this.excludeFromSignature = excludeFromSignature;
    }

    public boolean isExcludeFromCertificate() {
        return excludeFromCertificate;
    }

    public void setExcludeFromCertificate(boolean excludeFromCertificate) {
        this.excludeFromCertificate = excludeFromCertificate;
    }

    public ModifiableInteger getValue() {
        return value;
    }

    public void setValue(ModifiableInteger value) {
        this.value = value;
    }
}
