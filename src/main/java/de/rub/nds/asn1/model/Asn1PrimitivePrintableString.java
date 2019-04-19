package de.rub.nds.asn1.model;

import de.rub.nds.asn1.TagClass;
import de.rub.nds.asn1.TagNumber;
import de.rub.nds.asn1.encoder.Asn1PrimitivePrintableStringEncoder;
import de.rub.nds.asn1.encoder.Asn1Encoder;
import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public final class Asn1PrimitivePrintableString extends Asn1Field {

    public static final int TAG_CLASS = TagClass.UNIVERSAL.getIntValue();
    public static final boolean IS_CONSTRUCTED = false;
    public static final int TAG_NUMBER = TagNumber.PRINTABLESTRING.getIntValue();

    @XmlElement
    private String printableStringValue = "";

    @XmlElement
    private ModifiableString printableStringValueModification = new ModifiableString();

    public Asn1PrimitivePrintableString() {
        super(TAG_CLASS, IS_CONSTRUCTED, TAG_NUMBER);
    }

    public String getPrintableStringValue() {
        return printableStringValue;
    }

    public void setPrintableStringValue(String printableStringValue) {
        this.printableStringValue = printableStringValue;
    }

    public ModifiableString getPrintableStringValueModification() {
        return printableStringValueModification;
    }

    public void setPrintableStringValueModification(ModifiableString printableStringValueModification) {
        this.printableStringValueModification = printableStringValueModification;
    }

    public void setPrintableStringValueModificationValue(String printableStringValue) {
        this.printableStringValueModification = ModifiableVariableFactory.safelySetValue(this.printableStringValueModification, printableStringValue);
    }

    public String getFinalPrintableStringValue() {
        return this.printableStringValueModification.getValue();
    }

    @Override
    public Asn1Encoder getEncoder() {
        return new Asn1PrimitivePrintableStringEncoder(this);
    }
}
