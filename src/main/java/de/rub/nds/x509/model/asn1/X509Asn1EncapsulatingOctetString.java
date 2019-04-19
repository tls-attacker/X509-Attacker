package de.rub.nds.x509.model.asn1;

import de.rub.nds.asn1.model.Asn1EncapsulatingOctetString;
import de.rub.nds.x509.model.X509Field;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1EncapsulatingOctetString extends X509Field<Asn1EncapsulatingOctetString> {

    public X509Asn1EncapsulatingOctetString() {
        super(new Asn1EncapsulatingOctetString());
    }
}
