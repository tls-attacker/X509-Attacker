package de.rub.nds.asn1.model;

import de.rub.nds.asn1.encoder.Asn1Encoder;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public abstract class Asn1Encodable {

    public abstract Asn1Encoder getEncoder();

    public abstract Asn1Field getAsn1Field();
}
