package de.rub.nds.x509attacker.asn1.model;

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

    @XmlElement
    private ModifiableInteger asn1IntegerValue;

    public Asn1Integer() {
        super();
        this.asn1IntegerValue = new ModifiableInteger();
    }

    public ModifiableInteger getAsn1IntegerValue() {
        return asn1IntegerValue;
    }

    public void setAsn1IntegerValue(ModifiableInteger asn1IntegerValue) {
        this.asn1IntegerValue = asn1IntegerValue;
    }

    @Override
    protected void encodeForParentLayer() {
        byte[] content = this.createContentBytes();
        super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
        super.setAsn1IsConstructed(false);
        super.setAsn1TagNumber(Asn1TagNumber.INTEGER.getIntValue());
        super.setAsn1Content(content);
        super.encodeForParentLayer();
    }

    private byte[] createContentBytes() {
        byte[] content;
        int intValue = this.asn1IntegerValue.getValue();
        int numberOfIntegerBytes = this.computeNumberOfIntegerBytes(intValue);
        if (numberOfIntegerBytes >= 1) {
            content = new byte[numberOfIntegerBytes];
            for (int i = numberOfIntegerBytes - 1; i >= 0; i--) {
                content[i] = (byte) (intValue & 0xFF);
                intValue = intValue >> 8;
            }
        } else {
            content = new byte[0];
            // todo: log warning that we default to empty byte array
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
