package de.rub.nds.x509attacker.x509.model.x509asn1types;

import de.rub.nds.x509attacker.asn1.model.Asn1Integer;
import de.rub.nds.x509attacker.x509.fieldmeta.Referenceable;
import de.rub.nds.x509attacker.x509.fieldmeta.X509Field;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1Integer extends Asn1Integer implements X509Field {

    @XmlAttribute
    private int id = 0;

    @XmlAttribute
    private boolean excludeFromSignature = false;

    @XmlAttribute
    private boolean excludeFromCertificate = false;

    @XmlAttribute
    private int fromId = 0;

    public X509Asn1Integer() {
        super();
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
