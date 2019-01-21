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

    public static final class Asn1UtcTimeValue extends Asn1Field {

        @XmlElement
        private ModifiableString asn1UtcTimeValue;

        public Asn1UtcTimeValue() {
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
     * value is the first child's encode() result. For constructed encoding, the default encode() method is called and
     * hence the encoding is performed in encodeForParentLayer().
     *
     * @return
     */
    @Override
    public byte[] encode() {
        List<Asn1RawField> fields = super.getAsn1ChildElements();
        byte[] result = null;
        if (fields.size() > 1 || this.preferConstructedEncoding == true) {
            result = super.encode();
        } else {
            if (fields.size() == 1 && fields.get(0) instanceof Asn1UtcTimeValue) {
                result = fields.get(0).encode();
            } else {
                throw new RuntimeException("Primitive encoding of " + Asn1TagNumber.UTCTIME.toString() + " must only contain exactly one child of type Asn1UtcTimeValue!");
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
