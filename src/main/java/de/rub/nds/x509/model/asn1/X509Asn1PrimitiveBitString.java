package de.rub.nds.x509.model.asn1;

import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.x509.model.X509Field;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1PrimitiveBitString extends X509Field<Asn1PrimitiveBitString> {

    public X509Asn1PrimitiveBitString() {
        super(new Asn1PrimitiveBitString());
    }

    public X509Asn1PrimitiveBitString(final byte[] bitStringValue, final int unusedBits) {
        super(new Asn1PrimitiveBitString());
        this.getAsn1Field().setBitStringValue(bitStringValue);
        this.getAsn1Field().setUnusedBits(unusedBits);
    }
}
