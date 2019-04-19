package de.rub.nds.x509.model.asn1;

import de.rub.nds.asn1.model.Asn1Boolean;
import de.rub.nds.x509.model.X509Field;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1Boolean extends X509Field<Asn1Boolean> {

    public X509Asn1Boolean() {
        super(new Asn1Boolean());
    }

    public X509Asn1Boolean(boolean booleanValue) {
        super(new Asn1Boolean());
        this.getAsn1Field().setBooleanValue(booleanValue);
    }
}
