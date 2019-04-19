package de.rub.nds.x509.model.asn1;

import de.rub.nds.asn1.model.Asn1Set;
import de.rub.nds.x509.model.X509FieldContainer;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1Set extends X509FieldContainer<Asn1Set> {

    public X509Asn1Set() {
        super(new Asn1Set());
    }
}
