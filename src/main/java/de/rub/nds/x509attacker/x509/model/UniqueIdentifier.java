package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.x509attacker.x509.model.defaultvalueholders.Asn1BitStringValueHolder;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class UniqueIdentifier extends Asn1BitStringValueHolder {

    public UniqueIdentifier() {
        super();
    }
}
