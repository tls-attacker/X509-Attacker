package de.rub.nds.x509attacker.x509.model.meta;

import de.rub.nds.x509attacker.x509.fieldmeta.ReferenceHolder;
import de.rub.nds.x509attacker.x509.fieldmeta.Referenceable;
import de.rub.nds.x509attacker.x509.model.x509asn1types.X509Asn1BitString;
import de.rub.nds.x509attacker.x509.model.x509asn1types.X509Asn1ObjectIdentifier;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Signature implements ReferenceHolder {

    @XmlAttribute
    private int fromId = 0;

    @XmlElement
    private X509Asn1ObjectIdentifier algorithmIdentifier = null; // Todo: Change type to SignatureAlgorithm once implemented

    @XmlElement
    private X509Asn1BitString signature = null; // Todo: Change type to SignatureValue once implemented

    public Signature() {

    }

    public int getFromId() {
        return fromId;
    }

    public void setFromId(int fromId) {
        this.fromId = fromId;
    }

    public X509Asn1ObjectIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    public void setAlgorithmIdentifier(X509Asn1ObjectIdentifier algorithmIdentifier) {
        this.algorithmIdentifier = algorithmIdentifier;
    }

    public X509Asn1BitString getSignature() {
        return signature;
    }

    public void setSignature(X509Asn1BitString signature) {
        this.signature = signature;
    }

    @Override
    public void setReferencedObject(Referenceable referenceable) {
        // Default implementation: Do nothing
    }

    @Override
    public void updateReferencedFields() {
        // Default implementation: Do nothing
    }
}
