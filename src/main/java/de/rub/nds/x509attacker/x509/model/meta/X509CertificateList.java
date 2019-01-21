package de.rub.nds.x509attacker.x509.model.meta;

import javax.xml.bind.annotation.*;
import java.util.LinkedList;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509CertificateList {

    @XmlElements(value = {
            @XmlElement(name = "x509Certificate", type = X509Certificate.class)
    })
    private List<X509Certificate> certificates;

    public X509CertificateList() {
        this.certificates = new LinkedList<>();
    }
}
