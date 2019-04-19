package de.rub.nds.asn1.model;

import de.rub.nds.asn1.TagClass;
import de.rub.nds.asn1.TagNumber;
import de.rub.nds.asn1.encoder.Asn1IntegerEncoder;
import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import org.bouncycastle.math.raw.Mod;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.math.BigInteger;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public final class Asn1Integer extends Asn1Field {

    public static final int TAG_CLASS = TagClass.UNIVERSAL.getIntValue();
    public static final boolean IS_CONSTRUCTED = false;
    public static final int TAG_NUMBER = TagNumber.INTEGER.getIntValue();

    @XmlElement
    private BigInteger integerValue = BigInteger.ZERO;

    @XmlElement
    private ModifiableBigInteger integerValueModification = new ModifiableBigInteger();

    public Asn1Integer() {
        super(TAG_CLASS, IS_CONSTRUCTED, TAG_NUMBER);
        this.setIntegerValue(BigInteger.ZERO);
    }

    public BigInteger getIntegerValue() {
        return integerValue;
    }

    public void setIntegerValue(BigInteger integerValue) {
        this.integerValue = integerValue;
    }

    public ModifiableBigInteger getIntegerValueModification() {
        return integerValueModification;
    }

    public void setIntegerValueModification(ModifiableBigInteger integerValueModification) {
        this.integerValueModification = integerValueModification;
    }

    public void setIntegerValueModificationValue(BigInteger integerValue) {
        this.integerValueModification = ModifiableVariableFactory.safelySetValue(this.integerValueModification, integerValue);
    }

    public BigInteger getFinalIntegerValue() {
        return this.integerValueModification.getValue();
    }

    @Override
    public Asn1Encoder getEncoder() {
        return new Asn1IntegerEncoder(this);
    }
}
