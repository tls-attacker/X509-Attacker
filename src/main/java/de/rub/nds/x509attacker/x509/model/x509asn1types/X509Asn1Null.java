package de.rub.nds.x509attacker.x509.model.x509asn1types;

import de.rub.nds.x509attacker.asn1.model.Asn1Null;
import de.rub.nds.x509attacker.x509.encoder.X509Encoder;
import de.rub.nds.x509attacker.x509.meta.LinkingException;
import de.rub.nds.x509attacker.x509.meta.Referenceable;
import de.rub.nds.x509attacker.x509.meta.X509Field;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1Null extends Asn1Null implements X509Field {

    @XmlAttribute
    private String id = null;

    @XmlAttribute
    private boolean excludeFromSignature = false;

    @XmlAttribute
    private boolean excludeFromCertificate = false;

    @XmlAttribute
    private String fromId = null;

    public X509Asn1Null() {
        super();
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

    @Override
    public String getFromId() {
        return fromId;
    }

    public void setFromId(String fromId) {
        this.fromId = fromId;
    }

    @Override
    public void setReferencedObject(Referenceable referenceable) throws LinkingException {
        // Default implementation: Do nothing
    }

    @Override
    public void updateReferencedFields() {
        // Default implementation: Do nothing
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
