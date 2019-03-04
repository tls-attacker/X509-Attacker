package de.rub.nds.x509attacker.x509.model.types.basiccertificate;

import de.rub.nds.x509attacker.x509.model.x509asn1types.X509Asn1BitString;
import de.rub.nds.x509attacker.x509.model.x509asn1types.X509Asn1Null;
import de.rub.nds.x509attacker.x509.model.x509asn1types.X509Asn1ObjectIdentifier;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Signature extends X509Asn1Null {

    @XmlElement
    private X509Asn1ObjectIdentifier algorithmIdentifier = null; // Todo: Change type to SignatureAlgorithm once implemented

    @XmlElement
    private X509Asn1BitString signatureValue = null; // Todo: Change type to SignatureValue once implemented

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

    @Override
    public byte[] encode() {
        byte[] encoded = null;
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
        return encoded;
    }
}
