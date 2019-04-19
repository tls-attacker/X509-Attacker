package de.rub.nds.asn1.model;

import de.rub.nds.asn1.encoder.Asn1ChoiceEncoder;
import de.rub.nds.asn1.encoder.Asn1Encoder;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1Choice extends Asn1Chooser {

    @XmlAnyElement(lax = true)
    private Asn1Encodable asn1Encodable = null;

    public Asn1Choice() {
        super();
    }

    public Asn1Encodable getAsn1Encodable() {
        return asn1Encodable;
    }

    public void setAsn1Encodable(Asn1Encodable asn1Encodable) {
        this.asn1Encodable = asn1Encodable;
    }

    @Override
    public Asn1Encodable getChosenAsn1Encodable() {
        return this.getAsn1Encodable();
    }

    @Override
    public Asn1Encoder getEncoder() {
        return new Asn1ChoiceEncoder(this);
    }

    @Override
    public Asn1Field getAsn1Field() {
        Asn1Field result = null;
        if(this.asn1Encodable != null) {
            result = this.asn1Encodable.getAsn1Field();
        }
        return result;
    }
}
