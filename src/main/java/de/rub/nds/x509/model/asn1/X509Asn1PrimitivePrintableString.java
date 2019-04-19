package de.rub.nds.x509.model.asn1;

import de.rub.nds.asn1.model.Asn1PrimitivePrintableString;
import de.rub.nds.x509.model.X509Field;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1PrimitivePrintableString extends X509Field<Asn1PrimitivePrintableString> {

    public X509Asn1PrimitivePrintableString() {
        super(new Asn1PrimitivePrintableString());
    }

    public X509Asn1PrimitivePrintableString(final String printableStringValue) {
        super(new Asn1PrimitivePrintableString());
        this.getAsn1Field().setPrintableStringValue(printableStringValue);
    }
}
