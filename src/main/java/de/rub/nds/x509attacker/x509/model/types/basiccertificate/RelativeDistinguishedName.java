package de.rub.nds.x509attacker.x509.model.types.basiccertificate;

import de.rub.nds.x509attacker.x509.model.asn1types.Asn1SetValueHolder;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class RelativeDistinguishedName extends Asn1SetValueHolder {

    public RelativeDistinguishedName() {
        super();
    }
}
