package de.rub.nds.x509attacker.x509.model.x509asn1types;

import de.rub.nds.x509attacker.asn1.model.Asn1RawField;
import de.rub.nds.x509attacker.asn1.model.Asn1Utf8String;
import de.rub.nds.x509attacker.x509.encoder.X509Encoder;
import de.rub.nds.x509attacker.x509.meta.Referenceable;
import de.rub.nds.x509attacker.x509.meta.X509Asn1ValueHolder;
import de.rub.nds.x509attacker.x509.meta.X509Field;

import javax.xml.bind.annotation.*;
import java.util.LinkedList;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1Utf8String extends Asn1Utf8String implements X509Field, X509Asn1ValueHolder {

    @XmlAttribute
    private String id = null;

    @XmlAttribute
    private boolean excludeFromSignature = false;

    @XmlAttribute
    private boolean excludeFromCertificate = false;

    @XmlAttribute
    private String fromId = null;

    @XmlAnyElement(lax = true)
    private List<Asn1RawField> values;

    public X509Asn1Utf8String() {
        super();
        this.values = new LinkedList<>();
    }

    @Override
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
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

    public List<Asn1RawField> getValues() {
        return values;
    }

    public void setValues(List<Asn1RawField> values) {
        this.values = values;
    }

    public void addValue(Asn1RawField value) {
        this.values.add(value);
    }

    @Override
    public String getFromId() {
        return fromId;
    }

    public void setFromId(String fromId) {
        this.fromId = fromId;
    }

    @Override
    public void setReferencedObject(Referenceable referenceable) {
        // Default implementation: Do nothing
    }

    @Override
    public void updateReferencedFields() {
        // Default implementation: Do nothing
    }

    @Override
    protected void encodeForParentLayer() {
        this.addFieldsToAsn1Utf8String();
        super.encodeForParentLayer();
    }

    private void addFieldsToAsn1Utf8String() {
        super.clearFields();
        for (Asn1RawField field : this.values) {
            super.addField(field);
        }
    }

    @Override
    public byte[] encode() {
        byte[] encoded = null;
        X509Encoder x509Encoder = X509Encoder.getReference();
        switch (x509Encoder.getEncodeMode()) {
            case CERTIFICATE:
                encoded = this.encodeForCertificate();
                break;

            case SIGNATURE:
                encoded = this.encodeForSignature();
                break;

            case ALL:
            default:
                encoded = super.encode();
                break;
        }
        return encoded;
    }

    private byte[] encodeForCertificate() {
        byte[] encoded = null;
        if (this.excludeFromCertificate == true) {
            encoded = new byte[0];
        } else {
            encoded = super.encode();
        }
        return encoded;
    }

    private byte[] encodeForSignature() {
        byte[] encoded = null;
        if (this.excludeFromSignature == true) {
            encoded = new byte[0];
        } else {
            encoded = super.encode();
        }
        return encoded;
    }
}
