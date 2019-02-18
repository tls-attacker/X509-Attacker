package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagClass;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagNumber;

import javax.xml.bind.annotation.*;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1PrintableString extends Asn1FieldContainer {

    @XmlAttribute
    private boolean preferConstructedEncoding = false;

    @XmlRootElement
    @XmlAccessorType(XmlAccessType.FIELD)
    public static final class Asn1PrintableStringItem extends Asn1Field {

        private static final String DEFAULT_PRINTABLE_STRING_VALUE = "";

        @XmlElement
        private String asn1PrintableStringValue = DEFAULT_PRINTABLE_STRING_VALUE;

        @XmlElement
        private ModifiableString asn1PrintableStringValueModification;

        public Asn1PrintableStringItem() {
            super();
            this.asn1PrintableStringValueModification = new ModifiableString();
        }

        public String getAsn1PrintableStringValue() {
            return asn1PrintableStringValue;
        }

        public void setAsn1PrintableStringValue(String asn1PrintableStringValue) {
            this.asn1PrintableStringValue = asn1PrintableStringValue;
        }

        public ModifiableString getAsn1PrintableStringValueModification() {
            return asn1PrintableStringValueModification;
        }

        public void setAsn1PrintableStringValueModification(ModifiableString asn1PrintableStringValueModification) {
            this.asn1PrintableStringValueModification = asn1PrintableStringValueModification;
        }

        @Override
        protected void encodeForParentLayer() {
            this.updateDefaultValues();
            byte[] content = this.createContentBytes();
            super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
            super.setAsn1IsConstructed(false);
            super.setAsn1TagNumber(Asn1TagNumber.PRINTABLESTRING.getIntValue());
            super.setAsn1Content(content);
            super.encodeForParentLayer();
        }

        private void updateDefaultValues() {
            if (this.asn1PrintableStringValueModification.getOriginalValue() == null) {
                this.asn1PrintableStringValueModification = ModifiableVariableFactory.safelySetValue(this.asn1PrintableStringValueModification, this.asn1PrintableStringValue);
            }
        }

        private byte[] createContentBytes() {
            byte[] contentBytes = null;
            if (this.asn1PrintableStringValueModification != null) {
                contentBytes = this.asn1PrintableStringValueModification.getValue().getBytes();
            }
            return contentBytes;
        }
    }

    public Asn1PrintableString() {
        super();
    }

    public boolean isPreferConstructedEncoding() {
        return preferConstructedEncoding;
    }

    public void setPreferConstructedEncoding(boolean preferConstructedEncoding) {
        this.preferConstructedEncoding = preferConstructedEncoding;
    }

    /**
     * Overriding encode() to switch between primitive and constructed encoding. For primitive encoding, the return
     * value is the first child's encode() result. For constructed encoding, the default encode() method is called and
     * hence the encoding is performed in encodeForParentLayer().
     *
     * @return
     */
    @Override
    public byte[] encode() {
        List<Asn1RawField> fields = null;
        this.encodeForParentLayer();
        fields = super.getAsn1ChildElements();
        byte[] result = null;
        if (fields.size() > 1 || this.preferConstructedEncoding == true) {
            result = super.encode();
        } else {
            if (fields.size() == 1 && fields.get(0) instanceof Asn1PrintableStringItem) {
                result = fields.get(0).encode();
            } else {
                throw new RuntimeException("Primitive encoding of " + Asn1TagNumber.PRINTABLESTRING.toString() + " must only contain exactly one child of type Asn1PrintableStringItem!");
            }
        }
        return result;
    }

    @Override
    protected void encodeForParentLayer() {
        super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
        super.setAsn1IsConstructed(true);
        super.setAsn1TagNumber(Asn1TagNumber.PRINTABLESTRING.getIntValue());
        super.encodeForParentLayer();
    }
}
