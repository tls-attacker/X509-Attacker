package de.rub.nds.x509.model.asn1;

import de.rub.nds.asn1.model.Asn1PrimitiveUtcTime;
import de.rub.nds.x509.model.X509Field;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1PrimitiveUtcTime extends X509Field<Asn1PrimitiveUtcTime> {

    public X509Asn1PrimitiveUtcTime() {
        super(new Asn1PrimitiveUtcTime());
    }

    public X509Asn1PrimitiveUtcTime(final String utcTimeValue) {
        super(new Asn1PrimitiveUtcTime());
        this.getAsn1Field().setUtcTimeValue(utcTimeValue);
    }
}
