package de.rub.nds.x509attacker.x509.model.extensions.issueralternativename;

import de.rub.nds.x509attacker.x509.model.extensions.subjectalternativename.GeneralNames;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class IssuerAltName extends GeneralNames {

    public IssuerAltName() {
        super();
    }
}
