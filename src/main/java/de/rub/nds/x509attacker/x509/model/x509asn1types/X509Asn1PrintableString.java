package de.rub.nds.x509attacker.x509.model.x509asn1types;

import de.rub.nds.x509attacker.asn1.model.Asn1PrintableString;
import de.rub.nds.x509attacker.asn1.model.Asn1RawField;
import de.rub.nds.x509attacker.x509.fieldmeta.Referenceable;
import de.rub.nds.x509attacker.x509.fieldmeta.X509Asn1ValueHolder;
import de.rub.nds.x509attacker.x509.fieldmeta.X509Field;

import javax.xml.bind.annotation.*;
import java.util.LinkedList;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1PrintableString extends Asn1PrintableString implements X509Field, X509Asn1ValueHolder {

    @XmlAttribute
    private int id = 0;

    @XmlAttribute
    private boolean excludeFromSignature = false;

    @XmlAttribute
    private boolean excludeFromCertificate = false;

    @XmlAttribute
    private int fromId = 0;

    @XmlAnyElement(lax = true)
    private List<Asn1RawField> values;

    public X509Asn1PrintableString() {
        super();
        this.values = new LinkedList<>();
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

    public List<Asn1RawField> getValues() {
        return values;
    }

    public void setValues(List<Asn1RawField> values) {
        this.values = values;
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
        this.addFieldsToAsn1PrintableString();
        super.encodeForParentLayer();
    }

    private void addFieldsToAsn1PrintableString() {
        for (Asn1RawField field : this.values) {
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
