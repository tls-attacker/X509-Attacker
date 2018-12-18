package de.rub.nds.x509attacker.x509.model.extensions.subjectalternativename;

import de.rub.nds.x509attacker.x509.model.defaultvalueholders.Asn1SequenceValueHolder;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class GeneralNames extends Asn1SequenceValueHolder {

    public GeneralNames() {
        super();
    }
}
