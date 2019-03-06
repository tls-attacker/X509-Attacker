package de.rub.nds.x509attacker.x509.model.types.basiccertificate;

import de.rub.nds.x509attacker.x509.encoder.EncodeMode;
import de.rub.nds.x509attacker.x509.encoder.X509Encoder;
import de.rub.nds.x509attacker.x509.meta.LinkingException;
import de.rub.nds.x509attacker.x509.meta.Referenceable;
import de.rub.nds.x509attacker.x509.model.nonasn1.RealSignatureInfo;
import de.rub.nds.x509attacker.x509.model.x509asn1types.X509Asn1BitString;
import de.rub.nds.x509attacker.x509.model.x509asn1types.X509Asn1Null;
import de.rub.nds.x509attacker.x509.model.x509asn1types.X509Asn1ObjectIdentifier;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Signature extends X509Asn1Null {

    @XmlElement
    private X509Asn1ObjectIdentifier algorithmIdentifier = null; // Todo: Change type to SignatureAlgorithm once implemented

    @XmlElement
    private X509Asn1BitString signatureValue = null; // Todo: Change type to SignatureValue once implemented

    @XmlTransient
    private RealSignatureInfo realSignatureInfo = null;

    public Signature() {

    }

    public X509Asn1ObjectIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    public void setAlgorithmIdentifier(X509Asn1ObjectIdentifier algorithmIdentifier) {
        this.algorithmIdentifier = algorithmIdentifier;
    }

    public X509Asn1BitString getSignatureValue() {
        return signatureValue;
    }

    public void setSignatureValue(X509Asn1BitString signatureValue) {
        this.signatureValue = signatureValue;
    }

    public RealSignatureInfo getRealSignatureInfo() {
        return realSignatureInfo;
    }

    public void setRealSignatureInfo(RealSignatureInfo realSignatureInfo) {
        this.realSignatureInfo = realSignatureInfo;
    }

    @Override
    public byte[] encode() {
        byte[] encoded = null;
        X509Encoder x509Encoder = X509Encoder.getReference();
        if (x509Encoder.getEncodeMode() != EncodeMode.SIGNATURE) { // Do not encode if encode mode indicates encoding for signature computation
            byte[] encodedSignatureAlgorithm = new byte[0];
            byte[] encodedSignatureValue = new byte[0];
            if (this.algorithmIdentifier != null) {
                encodedSignatureAlgorithm = this.algorithmIdentifier.encode();
            }
            if (this.signatureValue != null) {
                encodedSignatureValue = this.signatureValue.encode();
            }
            encoded = new byte[encodedSignatureAlgorithm.length + encodedSignatureValue.length];
            System.arraycopy(encodedSignatureAlgorithm, 0, encoded, 0, encodedSignatureAlgorithm.length);
            System.arraycopy(encodedSignatureValue, 0, encoded, encodedSignatureAlgorithm.length, encodedSignatureValue.length);
        } else {
            encoded = new byte[0];
        }
        return encoded;
    }

    @Override
    public void setReferencedObject(Referenceable referenceable) throws LinkingException {
        if (referenceable instanceof RealSignatureInfo) {
            this.realSignatureInfo = (RealSignatureInfo) referenceable;
        } else {
            throw new LinkingException(this.getClass().toString() + " cannot handle a reference to object of type " + referenceable.getClass().toString() + "!");
        }
    }
}
