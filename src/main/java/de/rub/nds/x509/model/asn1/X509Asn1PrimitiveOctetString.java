package de.rub.nds.x509.model.asn1;

import de.rub.nds.asn1.model.Asn1PrimitiveOctetString;
import de.rub.nds.x509.model.X509Field;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1PrimitiveOctetString extends X509Field<Asn1PrimitiveOctetString> {

    public X509Asn1PrimitiveOctetString() {
        super(new Asn1PrimitiveOctetString());
    }

    public X509Asn1PrimitiveOctetString(final byte[] octetStringValue) {
        super(new Asn1PrimitiveOctetString());
        this.getAsn1Field().setOctetStringValue(octetStringValue);
    }
}
