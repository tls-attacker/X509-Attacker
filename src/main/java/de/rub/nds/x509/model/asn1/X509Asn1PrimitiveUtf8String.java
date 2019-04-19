package de.rub.nds.x509.model.asn1;

import de.rub.nds.asn1.model.Asn1PrimitiveUtf8String;
import de.rub.nds.x509.model.X509Field;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1PrimitiveUtf8String extends X509Field<Asn1PrimitiveUtf8String> {

    public X509Asn1PrimitiveUtf8String() {
        super(new Asn1PrimitiveUtf8String());
    }

    public X509Asn1PrimitiveUtf8String(final String utf8StringValue) {
        super(new Asn1PrimitiveUtf8String());
        this.getAsn1Field().setUtf8StringValue(utf8StringValue);
    }
}
