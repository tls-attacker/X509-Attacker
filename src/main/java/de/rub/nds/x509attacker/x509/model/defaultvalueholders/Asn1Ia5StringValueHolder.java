package de.rub.nds.x509attacker.x509.model.defaultvalueholders;

import de.rub.nds.x509attacker.asn1.model.Asn1Ia5String;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1Ia5StringValueHolder extends Asn1Ia5String {

    @XmlAttribute
    private boolean excludeFromSignature = false;

    @XmlAttribute
    private boolean excludeFromCertificate = false;

    public Asn1Ia5StringValueHolder() {
        super();
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
}
