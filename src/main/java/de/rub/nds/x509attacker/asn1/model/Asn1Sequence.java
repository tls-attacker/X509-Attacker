package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagClass;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagNumber;

import javax.xml.bind.annotation.*;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1Sequence extends Asn1FieldContainer {

    public Asn1Sequence() {
        super();
    }

    @Override
    protected void encodeForParentLayer() {
        super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
        super.setAsn1IsConstructed(false);
        super.setAsn1TagNumber(Asn1TagNumber.SEQUENCE.getIntValue());
        super.encodeForParentLayer();
    }
}
