package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagClass;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagNumber;

import javax.xml.bind.annotation.*;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1T61String extends Asn1FieldContainer {

    @XmlAttribute
    private boolean preferConstructedEncoding = false;

    // Todo: Implement conversion of characters to t.61 character set
    @XmlRootElement
    @XmlAccessorType(XmlAccessType.FIELD)
    public static final class Asn1T61StringItem extends Asn1Field {

        private static final String DEFAULT_T61_STRING_VALUE = "";

        @XmlElement
        private String asn1T61StringValue = DEFAULT_T61_STRING_VALUE;

        @XmlElement
        private ModifiableString asn1T61StringValueModification;

        public Asn1T61StringItem() {
            super();
            this.asn1T61StringValueModification = new ModifiableString();
        }

        public String getAsn1T61StringValue() {
            return asn1T61StringValue;
        }

        public void setAsn1T61StringValue(String asn1T61StringValue) {
            this.asn1T61StringValue = asn1T61StringValue;
        }

        public ModifiableString getAsn1T61StringValueModification() {
            return asn1T61StringValueModification;
        }

        public void setAsn1T61StringValueModification(ModifiableString asn1T61StringValueModification) {
            this.asn1T61StringValueModification = asn1T61StringValueModification;
        }

        @Override
        protected void encodeForParentLayer() {
            this.updateDefaultValues();
            byte[] content = this.createContentBytes();
            super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
            super.setAsn1IsConstructed(false);
            super.setAsn1TagNumber(Asn1TagNumber.T61STRING.getIntValue());
            super.setAsn1Content(content);
            super.encodeForParentLayer();
        }

        private void updateDefaultValues() {
            if (this.asn1T61StringValueModification.getOriginalValue() == null) {
                this.asn1T61StringValueModification = ModifiableVariableFactory.safelySetValue(this.asn1T61StringValueModification, this.asn1T61StringValue);
            }
        }

        private byte[] createContentBytes() {
            byte[] contentBytes = null;
            if (this.asn1T61StringValueModification != null) {
                contentBytes = this.asn1T61StringValueModification.getValue().getBytes();
            }
            return contentBytes;
        }
    }

    public Asn1T61String() {
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
            if (fields.size() == 1 && fields.get(0) instanceof Asn1T61StringItem) {
                result = fields.get(0).encode();
            } else {
                throw new RuntimeException("Primitive encoding of " + Asn1TagNumber.T61STRING.toString() + " must only contain exactly one child of type Asn1T61StringItem!");
            }
        }
        return result;
    }

    @Override
    protected void encodeForParentLayer() {
        super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
        super.setAsn1IsConstructed(true);
        super.setAsn1TagNumber(Asn1TagNumber.T61STRING.getIntValue());
        super.encodeForParentLayer();
    }
}
