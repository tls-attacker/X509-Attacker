package de.rub.nds.x509attacker.x509.model.types.extendedkeyusage;

import de.rub.nds.x509attacker.x509.model.asn1types.Asn1ObjectIdentifierValueHolder;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyPurposeId extends Asn1ObjectIdentifierValueHolder {

    public KeyPurposeId() {
        super();
    }
}
