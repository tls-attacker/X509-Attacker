package de.rub.nds.x509attacker.x509.model.extensions.nameconstraints;

import de.rub.nds.x509attacker.x509.model.defaultvalueholders.Asn1IntegerValueHolder;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class BaseDistance extends Asn1IntegerValueHolder {

    public BaseDistance() {
        super();
    }
}
