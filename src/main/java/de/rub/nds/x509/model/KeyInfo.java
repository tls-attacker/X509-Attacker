package de.rub.nds.x509.model;

import de.rub.nds.x509.linker.Linkeable;
import de.rub.nds.x509.model.rfc5280.X509Certificate;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyInfo implements Linkeable {

    @XmlAttribute
    private String id = "";

    @XmlAttribute
    private String fromId = "";

    @XmlAttribute
    private String keyFile = "";

    @XmlTransient
    private X509Certificate referencedX509Certificate = null;

    @XmlTransient
    private KeyInfo referencedKeyInfo = null;

    public KeyInfo() {
        super();
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public void setId(String id) {
        this.id = id;
    }

    @Override
    public String getFromId() {
        return fromId;
    }

    @Override
    public void setFromId(String fromId) {
        this.fromId = fromId;
    }

    public String getKeyFile() {
        return keyFile;
    }

    public void setKeyFile(String keyFile) {
        this.keyFile = keyFile;
    }

    public X509Certificate getReferencedX509Certificate() {
        return referencedX509Certificate;
    }

    public void setReferencedX509Certificate(X509Certificate referencedX509Certificate) {
        this.referencedX509Certificate = referencedX509Certificate;
    }

    public KeyInfo getReferencedKeyInfo() {
        return referencedKeyInfo;
    }

    public void setReferencedKeyInfo(KeyInfo referencedKeyInfo) {
        this.referencedKeyInfo = referencedKeyInfo;
    }

    @Override
    public void updateWithReferencedObject(Object object) {
        if(object instanceof X509Certificate) {
            this.referencedX509Certificate = (X509Certificate) object;
        }
        if(object instanceof KeyInfo) {
            this.referencedKeyInfo = (KeyInfo) object;
        }
    }
}
