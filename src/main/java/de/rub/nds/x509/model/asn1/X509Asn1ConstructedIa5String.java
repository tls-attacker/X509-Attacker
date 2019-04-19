package de.rub.nds.x509.model.asn1;

import de.rub.nds.asn1.model.Asn1ConstructedIa5String;
import de.rub.nds.x509.model.X509Field;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1ConstructedIa5String extends X509Field<Asn1ConstructedIa5String> {

    public X509Asn1ConstructedIa5String() {
        super(new Asn1ConstructedIa5String());
    }
}
