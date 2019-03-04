package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagClass;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagNumber;

import javax.xml.bind.annotation.*;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1UtcTime extends Asn1FieldContainer {

    @XmlAttribute
    private boolean preferConstructedEncoding = false;

    @XmlRootElement
    @XmlAccessorType(XmlAccessType.FIELD)
    public static final class Asn1UtcTimeItem extends Asn1Field {

        private static final String DEFAULT_UTC_TIME_VALUE = "99991231235959Z";

        @XmlElement
        private String asn1UtcTimeValue = DEFAULT_UTC_TIME_VALUE;

        @XmlElement
        private ModifiableString asn1UtcTimeValueModification;

        public Asn1UtcTimeItem() {
            super();
            this.asn1UtcTimeValueModification = new ModifiableString();
        }

        public String getAsn1UtcTimeValue() {
            return asn1UtcTimeValue;
        }

        public void setAsn1UtcTimeValue(String asn1UtcTimeValue) {
            this.asn1UtcTimeValue = asn1UtcTimeValue;
        }

        public ModifiableString getAsn1UtcTimeValueModification() {
            return asn1UtcTimeValueModification;
        }

        public void setAsn1UtcTimeValueModification(ModifiableString asn1UtcTimeValueModification) {
            this.asn1UtcTimeValueModification = asn1UtcTimeValueModification;
        }

        @Override
        protected void encodeForParentLayer() {
            this.updateDefaultValues();
            byte[] content = this.createContentBytes();
            super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
            super.setAsn1IsConstructed(false);
            super.setAsn1TagNumber(Asn1TagNumber.UTCTIME.getIntValue());
            super.setAsn1Content(content);
            super.encodeForParentLayer();
        }

        private void updateDefaultValues() {
            if (this.asn1UtcTimeValueModification.getOriginalValue() == null) {
                this.asn1UtcTimeValueModification = ModifiableVariableFactory.safelySetValue(this.asn1UtcTimeValueModification, this.asn1UtcTimeValue);
            }
        }

        private byte[] createContentBytes() {
            byte[] contentBytes = null;
            if (this.asn1UtcTimeValueModification != null) {
                contentBytes = this.asn1UtcTimeValueModification.getValue().getBytes();
            }
            return contentBytes;
        }
    }

    public Asn1UtcTime() {
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
     * asn1UtcTimeValueModification is the first child's encode() result. For constructed encoding, the default encode() method is called and
     * hence the encoding is performed in encodeForParentLayer().
     *
     * @return
     */
    @Override
    public byte[] encode() {
        List<Asn1RawField> fields = null;
        byte[] result = null;
        this.encodeForParentLayer();
        fields = super.getAsn1ChildElements();
        if (fields.size() > 1 || this.preferConstructedEncoding == true) {
            result = super.encode();
        } else {
            if (fields.size() == 1 && fields.get(0) instanceof Asn1UtcTimeItem) {
                result = fields.get(0).encode();
            } else {
                throw new RuntimeException("Primitive encoding of " + Asn1TagNumber.UTCTIME.toString() + " must only contain exactly one child of type Asn1UtcTimeItem!");
            }
        }
        return result;
    }

    @Override
    protected void encodeForParentLayer() {
        super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
        super.setAsn1IsConstructed(true);
        super.setAsn1TagNumber(Asn1TagNumber.UTCTIME.getIntValue());
        super.encodeForParentLayer();
    }
}
