package de.rub.nds.x509.model;

import de.rub.nds.x509.model.asn1.X509Asn1BitString;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

/**
 * Non-standardized class SignatureValue acts as a helper for XML files to distinguish regular bit strings from bit
 * strings which represent a signature value. Also, only SignatureValue supports being generated from RealSignatureInfo
 * reference.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SignatureValue extends X509Asn1BitString {

    @XmlTransient
    private RealSignatureInfo referencedRealSignatureInfo = null;

    public SignatureValue() {
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
