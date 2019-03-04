package de.rub.nds.x509attacker.x509.model.nonasn1;

import de.rub.nds.x509attacker.x509.meta.LinkingException;
import de.rub.nds.x509attacker.x509.meta.ReferenceHolder;
import de.rub.nds.x509attacker.x509.meta.Referenceable;
import de.rub.nds.x509attacker.x509.model.types.basiccertificate.X509Certificate;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyInfo implements ReferenceHolder {

    @XmlAttribute
    private String fromId = null;

    @XmlAttribute
    private String keyFile = null;

    @XmlTransient
    private int keyFileId = 0;

    @XmlTransient
    private X509Certificate certificate = null;

    public KeyInfo() {

    }

    public String getFromId() {
        return fromId;
    }

    public void setFromId(String fromId) {
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
