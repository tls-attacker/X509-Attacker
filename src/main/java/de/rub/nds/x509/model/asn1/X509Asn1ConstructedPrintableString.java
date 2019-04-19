package de.rub.nds.x509.model.asn1;

import de.rub.nds.asn1.model.Asn1ConstructedPrintableString;
import de.rub.nds.x509.model.X509Field;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1ConstructedPrintableString extends X509Field<Asn1ConstructedPrintableString> {

    public X509Asn1ConstructedPrintableString() {
        super(new Asn1ConstructedPrintableString());
    }
}
