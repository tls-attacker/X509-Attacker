package de.rub.nds.x509attacker.x509.model.x509asn1types;

import de.rub.nds.x509attacker.asn1.model.Asn1RawField;
import de.rub.nds.x509attacker.asn1.model.Asn1Sequence;
import de.rub.nds.x509attacker.x509.fieldmeta.Referenceable;
import de.rub.nds.x509attacker.x509.fieldmeta.X509Asn1FieldHolder;
import de.rub.nds.x509attacker.x509.fieldmeta.X509Field;

import javax.xml.bind.annotation.*;
import java.util.LinkedList;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1Sequence extends Asn1Sequence implements X509Field, X509Asn1FieldHolder {

    @XmlAttribute
    private int id = 0;

    @XmlAttribute
    private boolean excludeFromSignature = false;

    @XmlAttribute
    private boolean excludeFromCertificate = false;

    @XmlAttribute
    private int fromId = 0;

    @XmlAnyElement(lax = true)
    private List<Asn1RawField> fields;

    @XmlTransient
    private int encodeMode = 0;

    public X509Asn1Sequence() {
        super();
        this.fields = new LinkedList<>();
    }

    @Override
    public int getId() {
        return id;
    }

    public void setId(int id) {
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

    public List<Asn1RawField> getFields() {
        return fields;
    }

    public void setFields(List<Asn1RawField> fields) {
        this.fields = fields;
    }

    @Override
    public int getFromId() {
        return fromId;
    }

    public void setFromId(int fromId) {
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
        this.addFieldsToAsn1Sequence();
        super.encodeForParentLayer();
    }

    private void addFieldsToAsn1Sequence() {
        for (Asn1RawField field : this.fields) {
            super.addField(field);
        }
    }

    @Override
    public byte[] encodeForCertificate() {
        byte[] encoded = null;
        if (this.excludeFromCertificate == true) {
            encoded = new byte[0];
        } else {
            encoded = this.encode();
        }
        return encoded;
    }

    @Override
    public byte[] encodeForSignature() {
        byte[] encoded = null;
        if (this.excludeFromSignature == true) {
            encoded = new byte[0];
        } else {
            encoded = this.encode();
        }
        return encoded;
    }
}
