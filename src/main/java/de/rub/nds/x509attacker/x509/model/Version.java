package de.rub.nds.x509attacker.x509.model;

import de.rub.nds.x509attacker.x509.model.defaultvalueholders.Asn1IntegerValueHolder;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Version extends Asn1IntegerValueHolder {

    public static final int DEFAULT_VERSION = 0;

    public Version() {
        super();
    }
}
