package de.rub.nds.x509.model.asn1;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1UtcTime extends X509Asn1Choice {

    public X509Asn1UtcTime() {
        super();
    }
}
