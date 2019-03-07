package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.x509attacker.asn1.adapters.BigIntegerAdapter;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagClass;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagNumber;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.math.BigInteger;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1Integer extends Asn1Field {

    private static final BigInteger DEFAULT_INTEGER_VALUE = new BigInteger("0", 10);

    @XmlElement
    @XmlJavaTypeAdapter(BigIntegerAdapter.class)
    private BigInteger asn1IntegerValue = DEFAULT_INTEGER_VALUE;

    @XmlElement
    private ModifiableBigInteger asn1IntegerValueModification = new ModifiableBigInteger();

    public Asn1Integer() {
        super();
    }

    public BigInteger getAsn1IntegerValue() {
        return asn1IntegerValue;
    }

    public void setAsn1IntegerValue(BigInteger asn1IntegerValue) {
        this.asn1IntegerValue = asn1IntegerValue;
    }

    public ModifiableBigInteger getAsn1IntegerValueModification() {
        return asn1IntegerValueModification;
    }

    public void setAsn1IntegerValueModification(ModifiableBigInteger asn1IntegerValueModification) {
        this.asn1IntegerValueModification = asn1IntegerValueModification;
    }

    @Override
    protected void encodeForParentLayer() {
        this.updateDefaultValues();
        byte[] content = this.createContentBytes();
        super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
        super.setAsn1IsConstructed(false);
        super.setAsn1TagNumber(Asn1TagNumber.INTEGER.getIntValue());
        super.setAsn1Content(content);
        super.encodeForParentLayer();
    }

    private void updateDefaultValues() {
        if (this.asn1IntegerValueModification.getOriginalValue() == null) {
            this.asn1IntegerValueModification = ModifiableVariableFactory.safelySetValue(this.asn1IntegerValueModification, this.asn1IntegerValue);
        }
    }

    private byte[] createContentBytes() {
        byte[] content;
        BigInteger intValue = this.asn1IntegerValueModification.getValue();
        content = intValue.toByteArray();
        return content;
    }

    private int computeNumberOfIntegerBytes(BigInteger intValue) {
        int numberOfIntegerBytes = (int) Math.ceil(intValue.bitLength() + 1);
        return numberOfIntegerBytes;
    }
}
