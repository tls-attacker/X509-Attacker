package de.rub.nds.x509attacker.x509.model.nonasn1;

import de.rub.nds.x509attacker.x509.meta.LinkingException;
import de.rub.nds.x509attacker.x509.meta.ReferenceHolder;
import de.rub.nds.x509attacker.x509.meta.Referenceable;
import de.rub.nds.x509attacker.x509.model.types.basiccertificate.AlgorithmIdentifier;
import de.rub.nds.x509attacker.x509.model.types.basiccertificate.X509Certificate;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class RealSignatureInfo implements Referenceable, ReferenceHolder {

    @XmlAttribute
    private String id = null;

    @XmlAttribute
    private String fromId = null;

    @XmlElement
    private AlgorithmIdentifier signatureAlgorithm = null;

    @XmlElement
    private KeyInfo keyInfo = null;

    @XmlTransient
    private X509Certificate certificate = null;

    public RealSignatureInfo() {

    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    @Override
    public String getFromId() {
        return fromId;
    }

    public void setFromId(String fromId) {
        this.fromId = fromId;
    }

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(AlgorithmIdentifier signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public KeyInfo getKeyInfo() {
        return keyInfo;
    }

    public void setKeyInfo(KeyInfo keyInfo) {
        this.keyInfo = keyInfo;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    @Override
    public void setReferencedObject(Referenceable referenceable) throws LinkingException {
        throw new LinkingException(this.getClass().toString() + " cannot handle a reference to object of type " + referenceable.getClass().toString() + "!");
    }

    @Override
    public void updateReferencedFields() {

    }
}
