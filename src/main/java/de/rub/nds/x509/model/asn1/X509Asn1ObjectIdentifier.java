package de.rub.nds.x509.model.asn1;

import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.x509.model.X509Field;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1ObjectIdentifier extends X509Field<Asn1ObjectIdentifier> {

    public X509Asn1ObjectIdentifier() {
        super(new Asn1ObjectIdentifier());
    }

    public X509Asn1ObjectIdentifier(final String objectIdentifierValue) {
        super(new Asn1ObjectIdentifier());
        this.getAsn1Field().setObjectIdentifierValue(objectIdentifierValue);
    }
}
