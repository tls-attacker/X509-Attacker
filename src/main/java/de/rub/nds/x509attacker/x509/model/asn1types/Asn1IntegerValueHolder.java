package de.rub.nds.x509attacker.x509.model.asn1types;

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
    private int value = 0;

    public Asn1IntegerValueHolder() {
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

    public int getValue() {
        return value;
    }

    public void setValue(int value) {
        this.value = value;
    }

    @Override
    protected void encodeForParentLayer() {
        super.getAsn1IntegerValue().setOriginalValue(this.value);
        super.encodeForParentLayer();
    }
}
