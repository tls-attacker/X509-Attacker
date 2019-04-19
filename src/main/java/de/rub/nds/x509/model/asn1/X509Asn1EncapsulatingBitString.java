package de.rub.nds.x509.model.asn1;

import de.rub.nds.asn1.model.Asn1EncapsulatingBitString;
import de.rub.nds.x509.model.X509Field;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1EncapsulatingBitString extends X509Field<Asn1EncapsulatingBitString> {

    public X509Asn1EncapsulatingBitString() {
        super(new Asn1EncapsulatingBitString());
    }
}
