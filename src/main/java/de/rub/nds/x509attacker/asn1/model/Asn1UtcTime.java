package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagClass;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagNumber;

import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import java.util.LinkedList;
import java.util.List;

public class Asn1UtcTime extends Asn1Field {

    @XmlElement
    private ModifiableString asn1UtcTimeValues;

    public Asn1UtcTime() {
        super();
        this.asn1UtcTimeValues = new ModifiableString();
    }

    public ModifiableString getAsn1UtcTimeValues() {
        return asn1UtcTimeValues;
    }

    public void setAsn1UtcTimeValues(ModifiableString asn1UtcTimeValues) {
        this.asn1UtcTimeValues = asn1UtcTimeValues;
    }

    @Override
    protected void encodeForParentLayer() {
        byte[] content = this.createContentBytes();
        super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
        super.setAsn1IsConstructed(false);
        super.setAsn1TagNumber(Asn1TagNumber.IA5STRING.getIntValue());
        super.setAsn1Content(content);
        super.encodeForParentLayer();
    }

    private byte[] createContentBytes() {
        byte[] contentBytes = null;
        if (this.asn1UtcTimeValues != null) {
            contentBytes = this.asn1UtcTimeValues.getValue().getBytes();
        }
        return contentBytes;
    }
}
