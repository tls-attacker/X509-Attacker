package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagClass;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagNumber;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import java.util.LinkedList;
import java.util.List;

public class Asn1UtcTime extends Asn1Field {

    @XmlElement
    private ModifiableString asn1UtcTimeValue;

    public Asn1UtcTime() {
        super();
        this.asn1UtcTimeValue = new ModifiableString();
    }

    public ModifiableString getAsn1UtcTimeValues() {
        return asn1UtcTimeValue;
    }

    public void setAsn1UtcTimeValue(ModifiableString asn1UtcTimeValue) {
        this.asn1UtcTimeValue = asn1UtcTimeValue;
    }

    public void setAsn1UtcTimeValue(String asn1UtcTimeValue) {
        this.asn1UtcTimeValue = ModifiableVariableFactory.safelySetValue(this.asn1UtcTimeValue, asn1UtcTimeValue);
    }

    @Override
    protected void encodeForParentLayer() {
        byte[] content = this.createContentBytes();
        super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
        super.setAsn1IsConstructed(false);
        super.setAsn1TagNumber(Asn1TagNumber.UTCTIME.getIntValue());
        super.setAsn1Content(content);
        super.encodeForParentLayer();
    }

    private byte[] createContentBytes() {
        byte[] contentBytes = null;
        if (this.asn1UtcTimeValue != null) {
            contentBytes = this.asn1UtcTimeValue.getValue().getBytes();
        }
        return contentBytes;
    }
}
