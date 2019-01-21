package de.rub.nds.x509attacker.x509.model.asn1types;

import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.x509attacker.asn1.model.Asn1ObjectIdentifier;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1ObjectIdentifierValueHolder extends Asn1ObjectIdentifier {

    @XmlAttribute
    private boolean excludeFromSignature = false;

    @XmlAttribute
    private boolean excludeFromCertificate = false;

    @XmlElement
    private String value;

    public Asn1ObjectIdentifierValueHolder() {
        super();
        this.value = new String();
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

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    @Override
    protected void encodeForParentLayer() {
        super.getAsn1ObjectIdentifierValue().setOriginalValue(this.value);
        super.encodeForParentLayer();
    }
}
