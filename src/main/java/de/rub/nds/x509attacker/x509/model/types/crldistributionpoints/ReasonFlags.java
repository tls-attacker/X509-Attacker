package de.rub.nds.x509attacker.x509.model.types.crldistributionpoints;

import de.rub.nds.x509attacker.x509.model.x509asn1types.X509Asn1BitString;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ReasonFlags extends X509Asn1BitString {

    public ReasonFlags() {
        super();
    }

    // Todo: Add methods to toggle content bits maybe
}
