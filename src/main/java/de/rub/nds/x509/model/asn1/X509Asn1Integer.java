package de.rub.nds.x509.model.asn1;

import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.x509.model.X509Field;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import java.math.BigInteger;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1Integer extends X509Field<Asn1Integer> {

    public X509Asn1Integer() {
        super(new Asn1Integer());
    }

    public X509Asn1Integer(final BigInteger integerValue) {
        super(new Asn1Integer());
        this.getAsn1Field().setIntegerValue(integerValue);
    }
}
