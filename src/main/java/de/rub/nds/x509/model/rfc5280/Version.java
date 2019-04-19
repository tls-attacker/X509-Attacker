package de.rub.nds.x509.model.rfc5280;

import de.rub.nds.x509.model.asn1.X509Asn1Integer;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import java.math.BigInteger;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Version extends X509Asn1Integer {

    public static final int DEFAULT_VERSION = 2;

    public Version() {
        super(BigInteger.valueOf(DEFAULT_VERSION));
    }
}
