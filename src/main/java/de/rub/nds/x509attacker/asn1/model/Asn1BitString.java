package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.util.ByteArrayAdapter;
import de.rub.nds.x509attacker.asn1.Asn1TagClass;
import de.rub.nds.x509attacker.asn1.Asn1TagNumber;

import javax.xml.bind.annotation.*;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1BitString extends Asn1FieldContainer {

    public static final Asn1TagClass TYPE_TAG_CLASS = Asn1TagClass.UNIVERSAL;
    public static final boolean TYPE_IS_CONSTRUCTED = true;
    public static final Asn1TagNumber TYPE_TAG_NUMBER = Asn1TagNumber.BIT_STRING;

    @XmlAttribute
    private boolean preferConstructedEncoding = false;

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
            if (fields.size() == 1 && fields.get(0) instanceof Asn1BitStringItem) {
                result = fields.get(0).encode();
            } else {
                throw new RuntimeException("Primitive encoding of " + Asn1TagNumber.BIT_STRING.toString() + " must only contain exactly one child of type Asn1BitStringItem or of type Asn1EncapsulatingBitStringItem!");
            }
        }
        return result;
    }

    @Override
    protected void encodeForParentLayer() {
        super.setAsn1TagClass(TYPE_TAG_CLASS.toString());
        super.setAsn1IsConstructed(TYPE_IS_CONSTRUCTED);
        super.setAsn1TagNumber(TYPE_TAG_NUMBER.getIntValue());
        super.encodeForParentLayer();
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

    @XmlRootElement
    @XmlAccessorType(XmlAccessType.FIELD)
    public static class Asn1BitStringItem extends Asn1Field {

        public static final Asn1TagClass TYPE_TAG_CLASS = Asn1TagClass.UNIVERSAL;
        public static final boolean TYPE_IS_CONSTRUCTED = false;
        public static final Asn1TagNumber TYPE_TAG_NUMBER = Asn1TagNumber.BIT_STRING;

        private static final byte DEFAULT_NUMBER_OF_UNUSED_BITS = 0;
        private static final byte[] DEFAULT_HEX_STRING = new byte[0];

        @XmlElement
        private byte asn1NumberOfUnusedBits = DEFAULT_NUMBER_OF_UNUSED_BITS;

        @XmlElement
        @XmlJavaTypeAdapter(ByteArrayAdapter.class)
        private byte[] asn1BitStringValue = DEFAULT_HEX_STRING;

        @XmlElement
        private ModifiableByte asn1NumberOfUnusedBitsModification;

        @XmlElement
        private ModifiableByteArray asn1BitStringValueModification;

        public Asn1BitStringItem() {
            super();
            this.asn1NumberOfUnusedBitsModification = new ModifiableByte();
            this.asn1BitStringValueModification = new ModifiableByteArray();
        }

        public byte getAsn1NumberOfUnusedBits() {
            return asn1NumberOfUnusedBits;
        }

        public void setAsn1NumberOfUnusedBits(byte asn1NumberOfUnusedBits) {
            this.asn1NumberOfUnusedBits = asn1NumberOfUnusedBits;
        }

        public void setAsn1NumberOfUnusedBits(int asn1NumberOfUnusedBits) {
            this.asn1NumberOfUnusedBits = (byte) asn1NumberOfUnusedBits;
        }

        public byte[] getAsn1BitStringValue() {
            return asn1BitStringValue;
        }

        public void setAsn1BitStringValue(byte[] asn1BitStringValue) {
            this.asn1BitStringValue = asn1BitStringValue;
        }

        public ModifiableByte getAsn1NumberOfUnusedBitsModification() {
            return asn1NumberOfUnusedBitsModification;
        }

        public void setAsn1NumberOfUnusedBitsModification(ModifiableByte asn1NumberOfUnusedBitsModification) {
            this.asn1NumberOfUnusedBitsModification = asn1NumberOfUnusedBitsModification;
        }

        public ModifiableByteArray getAsn1BitStringValueModification() {
            return asn1BitStringValueModification;
        }

        public void setAsn1BitStringValueModification(ModifiableByteArray asn1BitStringValueModification) {
            this.asn1BitStringValueModification = asn1BitStringValueModification;
        }

        @Override
        protected void encodeForParentLayer() {
            this.updateDefaultValues();
            byte[] content = this.createContentBytes();
            super.setAsn1TagClass(TYPE_TAG_CLASS.toString());
            super.setAsn1IsConstructed(TYPE_IS_CONSTRUCTED);
            super.setAsn1TagNumber(TYPE_TAG_NUMBER.getIntValue());
            super.setAsn1Content(content);
            super.encodeForParentLayer();
        }

        private byte[] createContentBytes() {
            byte[] contentBytes = null;
            byte[] bitString = this.asn1BitStringValueModification.getValue();
            contentBytes = new byte[bitString.length + 1];
            contentBytes[0] = this.asn1NumberOfUnusedBitsModification.getValue();
            for (int i = 0; i < bitString.length; i++) {
                contentBytes[i + 1] = bitString[i];
            }
            return contentBytes;
        }

        private void updateDefaultValues() {
            if (this.asn1NumberOfUnusedBitsModification.getOriginalValue() == null) {
                this.asn1NumberOfUnusedBitsModification = ModifiableVariableFactory.safelySetValue(this.asn1NumberOfUnusedBitsModification, this.asn1NumberOfUnusedBits);
            }
            if (this.asn1BitStringValueModification.getOriginalValue() == null) {
                this.asn1BitStringValueModification = ModifiableVariableFactory.safelySetValue(this.asn1BitStringValueModification, this.asn1BitStringValue);
            }
        }
    }

    @XmlRootElement
    @XmlAccessorType(XmlAccessType.FIELD)
    public static final class Asn1EncapsulatingBitStringItem extends Asn1BitStringItem {

        @XmlAnyElement(lax = true)
        private List<Asn1RawField> asn1ChildElements;

        public List<Asn1RawField> getAsn1ChildElements() {
            return asn1ChildElements;
        }

        public void setAsn1ChildElements(List<Asn1RawField> asn1ChildElements) {
            this.asn1ChildElements = asn1ChildElements;
        }

        public void addField(Asn1RawField field) {
            this.asn1ChildElements.add(field);
        }

        @Override
        protected void encodeForParentLayer() {
            byte[] content = this.createContentBytes();
            super.setAsn1BitStringValue(content);
            super.encodeForParentLayer();
        }

        private byte[] createContentBytes() {
            byte[] content;
            byte[][] containedFieldContents = new byte[this.asn1ChildElements.size()][];
            int totalSize = 0;
            int contentPos = 0;
            for (int i = 0; i < this.asn1ChildElements.size(); i++) {
                containedFieldContents[i] = this.asn1ChildElements.get(i).encode();
                totalSize += containedFieldContents[i].length;
            }
            content = new byte[totalSize];
            for (int i = 0; i < containedFieldContents.length; i++) {
                for (int j = 0; j < containedFieldContents[i].length; j++) {
                    content[contentPos] = containedFieldContents[i][j];
                    contentPos++;
                }
            }
            return content;
        }
    }
}
