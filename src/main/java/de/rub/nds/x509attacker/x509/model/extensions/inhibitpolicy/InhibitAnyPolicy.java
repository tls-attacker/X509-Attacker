package de.rub.nds.x509attacker.x509.model.extensions.inhibitpolicy;

import de.rub.nds.x509attacker.x509.model.extensions.policyconstraints.SkipCerts;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class InhibitAnyPolicy extends SkipCerts {

    public InhibitAnyPolicy() {
        super();
    }
}
