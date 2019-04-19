package de.rub.nds.x509.model;

import de.rub.nds.x509.model.rfc5280.AlgorithmIdentifier;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

/**
 * Non-standardized class SignatureAlgorithm acts as a helper for XML files to distinguish regular algorithm identifiers
 * from signature algorithm identifiers. Also, only SignatureAlgorithm supports being generated from RealSignatureInfo
 * reference.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SignatureAlgorithm extends AlgorithmIdentifier {

    @XmlTransient
    private RealSignatureInfo referencedRealSignatureInfo = null;

    public SignatureAlgorithm() {
        super();
    }

    public RealSignatureInfo getReferencedRealSignatureInfo() {
        return referencedRealSignatureInfo;
    }

    public void setReferencedRealSignatureInfo(RealSignatureInfo referencedRealSignatureInfo) {
        this.referencedRealSignatureInfo = referencedRealSignatureInfo;
    }

    @Override
    public void updateWithReferencedObject(Object object) {
        if (object instanceof RealSignatureInfo) {
            this.referencedRealSignatureInfo = (RealSignatureInfo) object;
        }
        super.updateWithReferencedObject(object);
    }
}
