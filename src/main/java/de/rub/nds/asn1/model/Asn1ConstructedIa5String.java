package de.rub.nds.asn1.model;

import de.rub.nds.asn1.TagClass;
import de.rub.nds.asn1.TagNumber;
import de.rub.nds.asn1.encoder.Asn1FieldContainerEncoder;
import de.rub.nds.asn1.encoder.Asn1Encoder;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public final class Asn1ConstructedIa5String extends Asn1FieldContainer {

    public static final int TAG_CLASS = TagClass.UNIVERSAL.getIntValue();
    public static final boolean IS_CONSTRUCTED = true;
    public static final int TAG_NUMBER = TagNumber.IA5STRING.getIntValue();

    public Asn1ConstructedIa5String() {
        super(TAG_CLASS, IS_CONSTRUCTED, TAG_NUMBER);
    }

    @Override
    public Asn1Encoder getEncoder() {
        return new Asn1FieldContainerEncoder(this);
    }
}
