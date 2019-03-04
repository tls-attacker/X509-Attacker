package de.rub.nds.x509attacker.x509.model.meta;

import de.rub.nds.x509attacker.x509.fieldmeta.LinkingException;
import de.rub.nds.x509attacker.x509.fieldmeta.ReferenceHolder;
import de.rub.nds.x509attacker.x509.fieldmeta.Referenceable;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyInfo implements ReferenceHolder {

    @XmlAttribute
    private int fromId;

    @XmlAttribute
    private String keyFile;

    @XmlTransient
    private int keyFileId = 0;

    @XmlTransient
    private X509Certificate certificate = null;

    public KeyInfo() {
        this.fromId = 0;
        this.keyFile = null;
    }

    public int getFromId() {
        return fromId;
    }

    public void setFromId(int fromId) {
        this.fromId = fromId;
    }

    public String getKeyFile() {
        return keyFile;
    }

    public void setKeyFile(String keyFile) {
        this.keyFile = keyFile;
    }

    public int getKeyFileId() {
        return keyFileId;
    }

    public void setKeyFileId(int keyFileId) {
        this.keyFileId = keyFileId;
    }

    @Override
    public void setReferencedObject(Referenceable referenceable) throws LinkingException {
        if (referenceable instanceof X509Certificate) {
            this.certificate = (X509Certificate) referenceable;
        } else {
            throw new LinkingException(this.getClass().toString() + " cannot handle a reference to object of type " + referenceable.getClass().toString() + "!");
        }
    }

    @Override
    public void updateReferencedFields() {
        if (this.certificate != null) {
            this.updateKeyFileIdByCertificate();
        }
    }

    private void updateKeyFileIdByCertificate() {
        this.keyFileId = this.certificate.getKeyFileId();
    }
}
