package de.rub.nds.x509attacker.x509.model.asn1types;

import de.rub.nds.x509attacker.asn1.model.Asn1Null;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1NullValueHolder extends Asn1Null {

    @XmlAttribute
    private boolean excludeFromSignature = false;

    @XmlAttribute
    private boolean excludeFromCertificate = false;

    public Asn1NullValueHolder() {
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
