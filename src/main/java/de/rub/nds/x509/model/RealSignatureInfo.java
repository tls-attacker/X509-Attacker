package de.rub.nds.x509.model;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.x509.linker.Linkeable;
import de.rub.nds.x509.model.rfc5280.AlgorithmIdentifier;

import javax.xml.bind.annotation.*;
import java.util.LinkedList;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class RealSignatureInfo implements Linkeable {

    @XmlAttribute
    private String id = "";

    @XmlAttribute
    private String fromId = "";

    @XmlElement
    private AlgorithmIdentifier algorithmIdentifier = null;

    @XmlElement
    private KeyInfo keyInfo = null;

    @XmlTransient
    private RealSignatureInfo referencedRealSignatureInfo = null;

    public RealSignatureInfo() {
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

    public AlgorithmIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    public void setAlgorithmIdentifier(AlgorithmIdentifier algorithmIdentifier) {
        this.algorithmIdentifier = algorithmIdentifier;
    }

    public KeyInfo getKeyInfo() {
        return keyInfo;
    }

    public void setKeyInfo(KeyInfo keyInfo) {
        this.keyInfo = keyInfo;
    }

    public RealSignatureInfo getReferencedRealSignatureInfo() {
        return referencedRealSignatureInfo;
    }

    public void setReferencedRealSignatureInfo(RealSignatureInfo referencedRealSignatureInfo) {
        this.referencedRealSignatureInfo = referencedRealSignatureInfo;
    }

    @Override
    public void updateWithReferencedObject(Object object) {
        if(object instanceof RealSignatureInfo) {
            this.referencedRealSignatureInfo = (RealSignatureInfo) object;
        }
    }
}
