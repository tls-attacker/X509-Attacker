package de.rub.nds.x509.model.asn1;

import de.rub.nds.asn1.model.Asn1Null;
import de.rub.nds.x509.model.X509Field;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1Null extends X509Field<Asn1Null> {

    public X509Asn1Null() {
        super(new Asn1Null());
    }
}
