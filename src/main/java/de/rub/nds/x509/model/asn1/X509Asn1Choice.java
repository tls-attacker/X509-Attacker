package de.rub.nds.x509.model.asn1;

import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.asn1.model.Asn1Choice;
import de.rub.nds.x509.encoder.X509Excludable;
import de.rub.nds.x509.encoder.X509Asn1ChoiceEncoder;
import de.rub.nds.x509.linker.Linkeable;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class X509Asn1Choice extends Asn1Choice implements Linkeable, X509Excludable {

    @XmlAttribute
    private String id = "";

    @XmlAttribute
    private String fromId = "";

    @XmlAttribute
    private boolean excludeFromSignature = false;

    @XmlAttribute
    private boolean excludeFromCertificate = false;

    public X509Asn1Choice() {
        super();
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public void setId(String id) {
        this.id = id;
    }

    @Override
    public String getFromId() {
        return fromId;
    }

    @Override
    public void setFromId(String fromId) {
        this.fromId = fromId;
    }

    @Override
    public boolean isExcludeFromSignature() {
        return excludeFromSignature;
    }

    @Override
    public void setExcludeFromSignature(boolean excludeFromSignature) {
        this.excludeFromSignature = excludeFromSignature;
    }

    @Override
    public boolean isExcludeFromCertificate() {
        return excludeFromCertificate;
    }

    @Override
    public void setExcludeFromCertificate(boolean excludeFromCertificate) {
        this.excludeFromCertificate = excludeFromCertificate;
    }

    @Override
    public Asn1Encoder getEncoder() {
        return new X509Asn1ChoiceEncoder(this);
    }

    @Override
    public void updateWithReferencedObject(Object object) {

    }
}
