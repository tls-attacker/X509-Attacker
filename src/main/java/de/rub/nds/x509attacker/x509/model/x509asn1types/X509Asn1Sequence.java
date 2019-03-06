package de.rub.nds.x509attacker.x509.model.x509asn1types;

import de.rub.nds.x509attacker.asn1.model.Asn1RawField;
import de.rub.nds.x509attacker.asn1.model.Asn1Sequence;
import de.rub.nds.x509attacker.x509.encoder.X509Encoder;
import de.rub.nds.x509attacker.x509.meta.Referenceable;
import de.rub.nds.x509attacker.x509.meta.X509Asn1FieldHolder;
import de.rub.nds.x509attacker.x509.meta.X509Field;

import javax.xml.bind.annotation.*;
import java.util.LinkedList;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1Sequence extends Asn1Sequence implements X509Field, X509Asn1FieldHolder {

    @XmlAttribute
    private String id = null;

    @XmlAttribute
    private boolean excludeFromSignature = false;

    @XmlAttribute
    private boolean excludeFromCertificate = false;

    @XmlAttribute
    private String fromId = null;

    @XmlAnyElement(lax = true)
    private List<Asn1RawField> fields;

    @XmlTransient
    private int encodeMode = 0;

    public X509Asn1Sequence() {
        super();
        this.fields = new LinkedList<>();
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

    public List<Asn1RawField> getFields() {
        return fields;
    }

    public void setFields(List<Asn1RawField> fields) {
        this.fields = fields;
    }

    public void clearFields() {
        this.fields.clear();
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
        this.addFieldsToAsn1Sequence();
        super.encodeForParentLayer();
    }

    private void addFieldsToAsn1Sequence() {
        super.clearFields();
        for (Asn1RawField field : this.fields) {
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

    @Override
    public <T extends Asn1RawField> T findField(final Class<T> type) {
        return this.findField(0, type);
    }

    @Override
    public <T extends Asn1RawField> T findField(final int pos, final Class<T> type) {
        T result = null;
        List<Asn1RawField> children = this.getFields();
        int occurrences = 0;
        for (Asn1RawField currentChild : children) {
            if (type.isInstance(currentChild)) {
                if (pos == occurrences) {
                    result = (T) currentChild;
                    break;
                }
                occurrences++;
            }
        }
        return result;
    }

    @Override
    public <T extends Asn1RawField> List<T> findAllFields(final Class<T> type) {
        List<T> resultList = new LinkedList<>();
        List<Asn1RawField> children = this.getFields();
        int occurrences = 0;
        for (Asn1RawField currentChild : children) {
            if (type.isInstance(currentChild)) {
                resultList.add((T) currentChild);
            }
        }
        return resultList;
    }

    @Override
    public Asn1RawField getFieldAtPos(final int pos) {
        Asn1RawField result = null;
        List<Asn1RawField> children = this.getFields();
        if (children.size() > pos) {
            result = children.get(pos);
        }
        return result;
    }

    @Override
    public <T extends Asn1RawField> int countFieldOccurrences(final Class<T> type) {
        List<Asn1RawField> children = this.getFields();
        int occurrences = 0;
        for (Asn1RawField currentChild : children) {
            if (type.isInstance(currentChild)) {
                occurrences++;
            }
        }
        return occurrences;
    }
}
