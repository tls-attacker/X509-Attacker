package de.rub.nds.x509.model;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.x509.model.rfc5280.X509Certificate;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAnyElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.LinkedList;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509CertificateList {

    @XmlAnyElement(lax = true)
    private List<X509Certificate> certificates = new LinkedList<>();

    public X509CertificateList() {
        super();
    }

    public List<X509Certificate> getCertificates() {
        return certificates;
    }

    public void setCertificates(List<X509Certificate> certificates) {
        this.certificates = certificates;
    }
}
