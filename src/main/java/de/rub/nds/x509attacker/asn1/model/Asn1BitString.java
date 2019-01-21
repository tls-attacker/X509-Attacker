package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagClass;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagNumber;

import javax.xml.bind.annotation.*;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1BitString extends Asn1FieldContainer {

    @XmlAttribute
    private boolean preferConstructedEncoding = false;

    @XmlRootElement
    @XmlAccessorType(XmlAccessType.FIELD)
    public static final class Asn1BitStringValue extends Asn1Field {

        @XmlElement
        private ModifiableByte asn1NumberOfUnusedBits;

        @XmlElement
        private ModifiableByteArray asn1BitStringValue;

        public Asn1BitStringValue() {
            super();
            this.asn1NumberOfUnusedBits = new ModifiableByte();
            this.asn1BitStringValue = new ModifiableByteArray();
        }

        public ModifiableByte getAsn1NumberOfUnusedBits() {
            return asn1NumberOfUnusedBits;
        }

        public void setAsn1NumberOfUnusedBits(ModifiableByte asn1NumberOfUnusedBits) {
            this.asn1NumberOfUnusedBits = asn1NumberOfUnusedBits;
        }

        public void setAsn1NumberOfUnusedBits(int numberOfUnusedBits) {
            this.asn1NumberOfUnusedBits = ModifiableVariableFactory.safelySetValue(this.asn1NumberOfUnusedBits, (byte) numberOfUnusedBits);
        }

        public ModifiableByteArray getAsn1BitStringValue() {
            return asn1BitStringValue;
        }

        public void setAsn1BitStringValue(ModifiableByteArray asn1BitStringValue) {
            this.asn1BitStringValue = asn1BitStringValue;
        }

        public void setAsn1BitStringValue(byte[] bitStringValue) {
            this.asn1BitStringValue = ModifiableVariableFactory.safelySetValue(this.asn1BitStringValue, bitStringValue);
        }

        @Override
        protected void encodeForParentLayer() {
            byte[] content = this.createContentBytes();
            super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
            super.setAsn1IsConstructed(false);
            super.setAsn1TagNumber(Asn1TagNumber.BIT_STRING.getIntValue());
            super.setAsn1Content(content);
            super.encodeForParentLayer();
        }

        private byte[] createContentBytes() {
            byte[] contentBytes;
            byte[] bitString = this.asn1BitStringValue.getValue();
            contentBytes = new byte[bitString.length + 1];
            contentBytes[0] = this.asn1NumberOfUnusedBits.getValue();
            for (int i = 0; i < bitString.length; i++) {
                contentBytes[i + 1] = bitString[i];
            }
            return contentBytes;
        }
    }

    public Asn1BitString() {
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
            if (fields.size() == 1 && fields.get(0) instanceof Asn1BitStringValue) {
                result = fields.get(0).encode();
            } else {
                throw new RuntimeException("Primitive encoding of " + Asn1TagNumber.BIT_STRING.toString() + " must only contain exactly one child of type Asn1BitStringValue!");
            }
        }
        return result;
    }

    @Override
    protected void encodeForParentLayer() {
        super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
        super.setAsn1IsConstructed(true);
        super.setAsn1TagNumber(Asn1TagNumber.BIT_STRING.getIntValue());
        super.encodeForParentLayer();
    }
}
