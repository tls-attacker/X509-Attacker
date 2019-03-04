package de.rub.nds.x509attacker.x509.model.meta;

import de.rub.nds.x509attacker.x509.fieldmeta.LinkingException;
import de.rub.nds.x509attacker.x509.fieldmeta.ReferenceHolder;
import de.rub.nds.x509attacker.x509.fieldmeta.Referenceable;
import de.rub.nds.x509attacker.x509.model.types.basiccertificate.AlgorithmIdentifier;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class RealSignatureInfo implements ReferenceHolder {

    @XmlAttribute
    private int id = 0;

    @XmlAttribute
    private int fromId = 0;

    @XmlElement
    private AlgorithmIdentifier signatureAlgorithm = null; // Todo: Change type to SignatureAlgorithm

    @XmlElement
    private KeyInfo keyInfo = null;

    @XmlTransient
    private X509Certificate certificate = null;

    public RealSignatureInfo() {

    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    @Override
    public int getFromId() {
        return fromId;
    }

    public void setFromId(int fromId) {
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
