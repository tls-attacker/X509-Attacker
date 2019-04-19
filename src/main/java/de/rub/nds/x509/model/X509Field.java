package de.rub.nds.x509.model;

import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.x509.encoder.X509Excludable;
import de.rub.nds.x509.encoder.X509FieldEncoder;
import de.rub.nds.x509.linker.Linkeable;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class X509Field<T extends Asn1Field> extends X509Encodable implements X509Excludable, Linkeable {

    @XmlAnyElement(lax = true)
    private T asn1Type = null;

    @XmlAttribute
    private String id = "";

    @XmlAttribute
    private String fromId = "";

    @XmlAttribute
    private boolean excludeFromSignature = false;

    @XmlAttribute
    private boolean excludeFromCertificate = false;

    public X509Field() {
        super();
    }

    public X509Field(T asn1Type) {
        super();
        this.asn1Type = asn1Type;
    }

    public T getAsn1Type() {
        return asn1Type;
    }

    public void setAsn1Type(T asn1Type) {
        this.asn1Type = asn1Type;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getFromId() {
        return fromId;
    }

    public void setFromId(String fromId) {
        this.fromId = fromId;
    }

    @Override
    public boolean isExcludeFromSignature() {
        return excludeFromSignature;
    }

    @Override
    public void setExcludeFromSignature(boolean excludeFromSignature) {
        this.excludeFromSignature = excludeFromSignature;
    }

    @Override
    public boolean isExcludeFromCertificate() {
        return excludeFromCertificate;
    }

    @Override
    public void setExcludeFromCertificate(boolean excludeFromCertificate) {
        this.excludeFromCertificate = excludeFromCertificate;
    }

    @Override
    public T getAsn1Field() {
        return this.asn1Type;
    }

    @Override
    public Asn1Encoder getEncoder() {
        return new X509FieldEncoder(this);
    }

    @Override
    public void updateWithReferencedObject(Object object) {
    }
}
