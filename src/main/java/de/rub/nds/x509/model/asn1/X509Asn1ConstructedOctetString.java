package de.rub.nds.x509.model.asn1;

import de.rub.nds.asn1.model.Asn1ConstructedOctetString;
import de.rub.nds.x509.model.X509Field;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1ConstructedOctetString extends X509Field<Asn1ConstructedOctetString> {

    public X509Asn1ConstructedOctetString() {
        super(new Asn1ConstructedOctetString());
    }
}
