package de.rub.nds.x509.model.asn1;

import de.rub.nds.asn1.model.Asn1PrimitiveT61String;
import de.rub.nds.x509.model.X509Field;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1PrimitiveT61String extends X509Field<Asn1PrimitiveT61String> {

    public X509Asn1PrimitiveT61String() {
        super(new Asn1PrimitiveT61String());
    }

    public X509Asn1PrimitiveT61String(final String t61StringValue) {
        super(new Asn1PrimitiveT61String());
        this.getAsn1Field().setT61StringValue(t61StringValue);
    }
}
