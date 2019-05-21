package de.rub.nds.asn1.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class KeyInfo extends Asn1PseudoType {

    @XmlElement(name = "keyFile")
    private String keyFile = "";

    public KeyInfo() {

    }

    public String getKeyFile() {
        return keyFile;
    }

    public void setKeyFile(String keyFile) {
        this.keyFile = keyFile;
    }
}
