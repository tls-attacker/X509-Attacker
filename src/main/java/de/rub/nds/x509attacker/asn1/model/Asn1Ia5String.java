package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagClass;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagNumber;

import javax.xml.bind.annotation.*;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1Ia5String extends Asn1FieldContainer {

    @XmlAttribute
    private boolean preferConstructedEncoding = false;

    @XmlRootElement
    @XmlAccessorType(XmlAccessType.FIELD)
    public static final class Asn1Ia5StringItem extends Asn1Field {

        private static final String DEFAULT_IA5_STRING_VALUE = "";

        @XmlElement
        private String asn1Ia5StringValue = DEFAULT_IA5_STRING_VALUE;

        @XmlElement
        private ModifiableString asn1Ia5StringValueModification;

        public Asn1Ia5StringItem() {
            super();
            this.asn1Ia5StringValueModification = new ModifiableString();
        }

        public String getAsn1Ia5StringValue() {
            return asn1Ia5StringValue;
        }

        public void setAsn1Ia5StringValue(String asn1Ia5StringValue) {
            this.asn1Ia5StringValue = asn1Ia5StringValue;
        }

        public ModifiableString getAsn1Ia5StringValueModification() {
            return asn1Ia5StringValueModification;
        }

        public void setAsn1Ia5StringValueModification(ModifiableString asn1Ia5StringValueModification) {
            this.asn1Ia5StringValueModification = asn1Ia5StringValueModification;
        }

        @Override
        protected void encodeForParentLayer() {
            this.updateDefaultValues();
            byte[] content = this.createContentBytes();
            super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
            super.setAsn1IsConstructed(false);
            super.setAsn1TagNumber(Asn1TagNumber.IA5STRING.getIntValue());
            super.setAsn1Content(content);
            super.encodeForParentLayer();
        }

        private byte[] createContentBytes() {
            byte[] contentBytes = null;
            if (this.asn1Ia5StringValueModification != null) {
                contentBytes = this.asn1Ia5StringValueModification.getValue().getBytes();
            }
            return contentBytes;
        }

        private void updateDefaultValues() {
            if (this.asn1Ia5StringValueModification.getOriginalValue() == null) {
                this.asn1Ia5StringValueModification = ModifiableVariableFactory.safelySetValue(this.asn1Ia5StringValueModification, this.asn1Ia5StringValue);
            }
        }
    }

    public Asn1Ia5String() {
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
            if (fields.size() == 1 && fields.get(0) instanceof Asn1Ia5StringItem) {
                result = fields.get(0).encode();
            } else {
                throw new RuntimeException("Primitive encoding of " + Asn1TagNumber.IA5STRING.toString() + " must only contain exactly one child of type Asn1Ia5StringItem!");
            }
        }
        return result;
    }

    @Override
    protected void encodeForParentLayer() {
        super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
        super.setAsn1IsConstructed(true);
        super.setAsn1TagNumber(Asn1TagNumber.IA5STRING.getIntValue());
        super.encodeForParentLayer();
    }
}
