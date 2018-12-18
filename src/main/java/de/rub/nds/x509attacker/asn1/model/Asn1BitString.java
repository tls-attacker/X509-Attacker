package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagClass;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagNumber;

import javax.xml.bind.annotation.*;
import java.util.LinkedList;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1BitString extends Asn1Field {

    @XmlElement
    private ModifiableByte asn1NumberOfUnusedBits;

    @XmlElement
    private ModifiableByteArray asn1BitStringValue;

    public Asn1BitString() {
        super();
        this.asn1NumberOfUnusedBits = new ModifiableByte();
        this.asn1BitStringValue = new ModifiableByteArray();
    }

    public ModifiableByte getAsn1NumberOfUnusedBits() {
        return asn1NumberOfUnusedBits;
    }

    public void setAsn1NumberOfUnusedBits(ModifiableByte asn1NumberOfUnusedBits) {
        this.asn1NumberOfUnusedBits = asn1NumberOfUnusedBits;
    }

    public ModifiableByteArray getAsn1BitStringValue() {
        return asn1BitStringValue;
    }

    public void setAsn1BitStringValue(ModifiableByteArray asn1BitStringValue) {
        this.asn1BitStringValue = asn1BitStringValue;
    }

    @Override
    protected void encodeForParentLayer() {
        byte[] content = this.createContentBytes();
        super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
        super.setAsn1IsConstructed(false);
        super.setAsn1TagNumber(Asn1TagNumber.BIT_STRING.getIntValue());
        super.setAsn1Content(content);
        super.encodeForParentLayer();
    }

    private byte[] createContentBytes() {
        byte[] contentBytes;
        byte[] bitString = this.asn1BitStringValue.getValue();
        contentBytes = new byte[bitString.length + 1];
        contentBytes[0] = this.asn1NumberOfUnusedBits.getValue();
        for (int i = 0; i < bitString.length; i++) {
            contentBytes[i + 1] = bitString[i];
        }
        return contentBytes;
    }
}
