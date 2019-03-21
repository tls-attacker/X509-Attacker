package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.x509attacker.asn1.Asn1TagClass;
import de.rub.nds.x509attacker.asn1.Asn1TagNumber;

import javax.xml.bind.annotation.*;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1Utf8String extends Asn1FieldContainer {

    @XmlAttribute
    private boolean preferConstructedEncoding = false;

    public Asn1Utf8String() {
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
            if (fields.size() == 1 && fields.get(0) instanceof Asn1Utf8StringItem) {
                result = fields.get(0).encode();
            } else {
                throw new RuntimeException("Primitive encoding of " + Asn1TagNumber.UTF8STRING.toString() + " must only contain exactly one child of type Asn1Utf8StringItem!");
            }
        }
        return result;
    }

    @Override
    protected void encodeForParentLayer() {
        super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
        super.setAsn1IsConstructed(true);
        super.setAsn1TagNumber(Asn1TagNumber.UTF8STRING.getIntValue());
        super.encodeForParentLayer();
    }

    @XmlRootElement
    @XmlAccessorType(XmlAccessType.FIELD)
    public static final class Asn1Utf8StringItem extends Asn1Field {

        private static final String DEFAULT_UTF8_STRING_VALUE = "";

        @XmlElement
        private String asn1Utf8StringValue = DEFAULT_UTF8_STRING_VALUE;

        @XmlElement
        private ModifiableString asn1Utf8StringValueModification = new ModifiableString();

        public Asn1Utf8StringItem() {
            super();
        }

        public String getAsn1Utf8StringValue() {
            return asn1Utf8StringValue;
        }

        public void setAsn1Utf8StringValue(String asn1Utf8StringValue) {
            this.asn1Utf8StringValue = asn1Utf8StringValue;
        }

        public ModifiableString getAsn1Utf8StringValueModification() {
            return asn1Utf8StringValueModification;
        }

        public void setAsn1Utf8StringValueModification(ModifiableString asn1Utf8StringValueModification) {
            this.asn1Utf8StringValueModification = asn1Utf8StringValueModification;
        }

        @Override
        protected void encodeForParentLayer() {
            this.updateDefaultValues();
            byte[] content = this.createContentBytes();
            super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
            super.setAsn1IsConstructed(false);
            super.setAsn1TagNumber(Asn1TagNumber.UTF8STRING.getIntValue());
            super.setAsn1Content(content);
            super.encodeForParentLayer();
        }

        private void updateDefaultValues() {
            if (this.asn1Utf8StringValueModification.getOriginalValue() == null) {
                this.asn1Utf8StringValueModification = ModifiableVariableFactory.safelySetValue(this.asn1Utf8StringValueModification, this.asn1Utf8StringValue);
            }
        }

        private byte[] createContentBytes() {
            byte[] contentBytes = null;
            if (this.asn1Utf8StringValueModification != null) {
                contentBytes = this.asn1Utf8StringValueModification.getValue().getBytes();
            }
            return contentBytes;
        }
    }
}
