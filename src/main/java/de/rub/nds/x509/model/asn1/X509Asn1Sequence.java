package de.rub.nds.x509.model.asn1;

import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509.model.X509FieldContainer;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1Sequence extends X509FieldContainer<Asn1Sequence> {

    public X509Asn1Sequence() {
        super(new Asn1Sequence());
    }
}
