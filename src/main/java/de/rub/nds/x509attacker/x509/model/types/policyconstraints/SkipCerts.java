package de.rub.nds.x509attacker.x509.model.types.policyconstraints;

import de.rub.nds.x509attacker.x509.model.x509asn1types.X509Asn1Integer;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SkipCerts extends X509Asn1Integer {

    public SkipCerts() {
        super();
    }
}
