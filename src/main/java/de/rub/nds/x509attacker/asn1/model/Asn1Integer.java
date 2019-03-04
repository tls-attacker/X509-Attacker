package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagClass;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagNumber;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1Integer extends Asn1Field {

    private static final int DEFAULT_INTEGER_VALUE = 0;

    @XmlElement
    private int asn1IntegerValue = DEFAULT_INTEGER_VALUE;

    @XmlElement
    private ModifiableInteger asn1IntegerValueModification;

    public Asn1Integer() {
        super();
        this.asn1IntegerValueModification = new ModifiableInteger();
    }

    public int getAsn1IntegerValue() {
        return asn1IntegerValue;
    }

    public void setAsn1IntegerValue(int asn1IntegerValue) {
        this.asn1IntegerValue = asn1IntegerValue;
    }

    public ModifiableInteger getAsn1IntegerValueModification() {
        return asn1IntegerValueModification;
    }

    public void setAsn1IntegerValueModification(ModifiableInteger asn1IntegerValueModification) {
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
        int intValue = this.asn1IntegerValueModification.getValue();
        int numberOfIntegerBytes = this.computeNumberOfIntegerBytes(intValue);
        if (numberOfIntegerBytes >= 1) {
            content = new byte[numberOfIntegerBytes];
            for (int i = numberOfIntegerBytes - 1; i >= 0; i--) {
                content[i] = (byte) (intValue & 0xFF);
                intValue = intValue >> 8;
            }
        } else {
            content = new byte[0];
        }
        return content;
    }

    private int computeNumberOfIntegerBytes(int intValue) {
        int numberOfIntegerBytes = 0;
        boolean isMsbSet = false;
        if (intValue < 0) {
            intValue = ~intValue;
        }
        if (intValue == 0) {
            numberOfIntegerBytes = 1;
        } else {
            while (intValue > 0) {
                numberOfIntegerBytes++;
                isMsbSet = (intValue & 0x80) != 0;
                intValue = intValue >> 8;
            }
            if (isMsbSet) {
                numberOfIntegerBytes++;
            }
        }
        return numberOfIntegerBytes;
    }
}
