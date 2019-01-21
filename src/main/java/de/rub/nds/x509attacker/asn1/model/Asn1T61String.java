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
    public static final class Asn1T61StringValue extends Asn1Field {

        @XmlElement
        private ModifiableString asn1T61StringValue;

        public Asn1T61StringValue() {
            super();
            this.asn1T61StringValue = new ModifiableString();
        }

        public ModifiableString getAsn1T61StringValue() {
            return asn1T61StringValue;
        }

        public void setAsn1T61StringValue(ModifiableString asn1T61StringValue) {
            this.asn1T61StringValue = asn1T61StringValue;
        }

        public void setAsn1T61StringValue(String asn1T61StringValue) {
            this.asn1T61StringValue = ModifiableVariableFactory.safelySetValue(this.asn1T61StringValue, asn1T61StringValue);
        }

        @Override
        protected void encodeForParentLayer() {
            byte[] content = this.createContentBytes();
            super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
            super.setAsn1IsConstructed(false);
            super.setAsn1TagNumber(Asn1TagNumber.T61STRING.getIntValue());
            super.setAsn1Content(content);
            super.encodeForParentLayer();
        }

        private byte[] createContentBytes() {
            byte[] contentBytes = null;
            if (this.asn1T61StringValue != null) {
                contentBytes = this.asn1T61StringValue.getValue().getBytes();
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
        List<Asn1RawField> fields = super.getAsn1ChildElements();
        byte[] result = null;
        if (fields.size() > 1 || this.preferConstructedEncoding == true) {
            result = super.encode();
        } else {
            if (fields.size() == 1 && fields.get(0) instanceof Asn1T61StringValue) {
                result = fields.get(0).encode();
            } else {
                throw new RuntimeException("Primitive encoding of " + Asn1TagNumber.T61STRING.toString() + " must only contain exactly one child of type Asn1T61StringValue!");
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
