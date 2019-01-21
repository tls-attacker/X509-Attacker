package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagClass;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagNumber;

import javax.xml.bind.annotation.*;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1OctetString extends Asn1FieldContainer {

    @XmlAttribute
    private boolean preferConstructedEncoding = false;

    @XmlRootElement
    @XmlAccessorType(XmlAccessType.FIELD)
    public static final class Asn1OctetStringValue extends Asn1Field {

        @XmlElement
        private ModifiableByteArray asn1OctetStringValue;

        public Asn1OctetStringValue() {
            super();
            this.asn1OctetStringValue = new ModifiableByteArray();
        }

        public ModifiableByteArray getAsn1OctetStringValue() {
            return asn1OctetStringValue;
        }

        public void setAsn1OctetStringValue(ModifiableByteArray asn1OctetStringValue) {
            this.asn1OctetStringValue = asn1OctetStringValue;
        }

        public void setAsn1OctetStringValue(byte[] asn1OctetStringValue) {
            this.asn1OctetStringValue = ModifiableVariableFactory.safelySetValue(this.asn1OctetStringValue, asn1OctetStringValue);
        }

        @Override
        protected void encodeForParentLayer() {
            byte[] content = this.createContentBytes();
            super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
            super.setAsn1IsConstructed(false);
            super.setAsn1TagNumber(Asn1TagNumber.OCTET_STRING.getIntValue());
            super.setAsn1Content(content);
            super.encodeForParentLayer();
        }

        private byte[] createContentBytes() {
            return this.asn1OctetStringValue.getValue();
        }
    }

    public Asn1OctetString() {
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
            if (fields.size() == 1 && fields.get(0) instanceof Asn1OctetStringValue) {
                result = fields.get(0).encode();
            } else {
                throw new RuntimeException("Primitive encoding of " + Asn1TagNumber.OCTET_STRING.toString() + " must only contain exactly one child of type Asn1OctetStringValue!");
            }
        }
        return result;
    }

    @Override
    protected void encodeForParentLayer() {
        super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
        super.setAsn1IsConstructed(true);
        super.setAsn1TagNumber(Asn1TagNumber.OCTET_STRING.getIntValue());
        super.encodeForParentLayer();
    }
}
