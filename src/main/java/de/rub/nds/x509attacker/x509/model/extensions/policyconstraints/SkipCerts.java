package de.rub.nds.x509attacker.x509.model.extensions.policyconstraints;

import de.rub.nds.x509attacker.x509.model.defaultvalueholders.Asn1IntegerValueHolder;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SkipCerts extends Asn1IntegerValueHolder {

    public SkipCerts() {
        super();
    }
}
