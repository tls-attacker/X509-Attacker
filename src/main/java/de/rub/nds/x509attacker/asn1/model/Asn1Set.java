package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.x509attacker.asn1.Asn1TagClass;
import de.rub.nds.x509attacker.asn1.Asn1TagNumber;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1Set extends Asn1FieldContainer {

    public Asn1Set() {
        super();
    }

    @Override
    protected void encodeForParentLayer() {
        super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
        super.setAsn1IsConstructed(true);
        super.setAsn1TagNumber(Asn1TagNumber.SET.getIntValue());
        super.encodeForParentLayer();
    }
}
