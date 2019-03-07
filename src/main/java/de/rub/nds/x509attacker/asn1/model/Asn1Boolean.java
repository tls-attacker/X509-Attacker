package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagClass;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagNumber;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1Boolean extends Asn1Field {

    private static final boolean DEFAULT_BOOLEAN_VALUE = false;

    @XmlElement
    private boolean asn1BooleanValue = DEFAULT_BOOLEAN_VALUE;

    @XmlElement
    private ModifiableBoolean asn1BooleanValueModification = new ModifiableBoolean();

    public Asn1Boolean() {
        super();
    }

    public boolean getAsn1BooleanValue() {
        return asn1BooleanValue;
    }

    public void setAsn1BooleanValue(boolean asn1BooleanValue) {
        this.asn1BooleanValue = asn1BooleanValue;
    }

    public ModifiableBoolean getAsn1BooleanValueModification() {
        return asn1BooleanValueModification;
    }

    public void setAsn1BooleanValueModification(ModifiableBoolean asn1BooleanValueModification) {
        this.asn1BooleanValueModification = asn1BooleanValueModification;
    }

    @Override
    protected void encodeForParentLayer() {
        this.updateDefaultValues();
        byte[] content = this.createContentBytes();
        super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
        super.setAsn1IsConstructed(false);
        super.setAsn1TagNumber(Asn1TagNumber.BOOLEAN.getIntValue());
        super.setAsn1Content(content);
        super.encodeForParentLayer();
    }

    private void updateDefaultValues() {
        if (this.asn1BooleanValueModification.getOriginalValue() == null) {
            this.asn1BooleanValueModification = ModifiableVariableFactory.safelySetValue(this.asn1BooleanValueModification, this.asn1BooleanValue);
        }
    }

    private byte[] createContentBytes() {
        byte[] content;
        boolean booleanValue = this.asn1BooleanValueModification.getValue();
        if (booleanValue == true) {
            content = new byte[]{(byte) 0xFF};
        } else {
            content = new byte[]{0};
        }
        return content;
    }
}
