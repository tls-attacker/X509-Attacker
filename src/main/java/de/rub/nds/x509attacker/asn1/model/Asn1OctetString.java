package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ByteArrayAdapter;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagClass;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagNumber;
import org.bouncycastle.math.raw.Mod;

import javax.xml.bind.annotation.*;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.util.List;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1OctetString extends Asn1FieldContainer {

    @XmlAttribute
    private boolean preferConstructedEncoding = false;

    @XmlRootElement
    @XmlAccessorType(XmlAccessType.FIELD)
    public static final class Asn1OctetStringItem extends Asn1Field {

        private static final byte[] DEFAULT_OCTET_STRING_VALUE = new byte[0];

        @XmlElement
        @XmlJavaTypeAdapter(ByteArrayAdapter.class)
        private byte[] asn1OctetStringValue = DEFAULT_OCTET_STRING_VALUE;

        @XmlElement
        private ModifiableByteArray asn1OctetStringValueModification;

        public Asn1OctetStringItem() {
            super();
            this.asn1OctetStringValueModification = new ModifiableByteArray();
        }

        public byte[] getAsn1OctetStringValue() {
            return asn1OctetStringValue;
        }

        public void setAsn1OctetStringValue(byte[] asn1OctetStringValue) {
            this.asn1OctetStringValue = asn1OctetStringValue;
        }

        public ModifiableByteArray getAsn1OctetStringValueModification() {
            return asn1OctetStringValueModification;
        }

        public void setAsn1OctetStringValueModification(ModifiableByteArray asn1OctetStringValueModification) {
            this.asn1OctetStringValueModification = asn1OctetStringValueModification;
        }

        @Override
        protected void encodeForParentLayer() {
            this.updateDefaultValues();
            byte[] content = this.createContentBytes();
            super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
            super.setAsn1IsConstructed(false);
            super.setAsn1TagNumber(Asn1TagNumber.OCTET_STRING.getIntValue());
            super.setAsn1Content(content);
            super.encodeForParentLayer();
        }

        private void updateDefaultValues() {
            if (this.asn1OctetStringValueModification.getOriginalValue() == null) {
                this.asn1OctetStringValueModification = ModifiableVariableFactory.safelySetValue(this.asn1OctetStringValueModification, this.asn1OctetStringValue);
            }
        }

        private byte[] createContentBytes() {
            return this.asn1OctetStringValueModification.getValue();
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
        List<Asn1RawField> fields = null;
        this.encodeForParentLayer();
        fields = super.getAsn1ChildElements();
        byte[] result = null;
        if (fields.size() > 1 || this.preferConstructedEncoding == true) {
            result = super.encode();
        } else {
            if (fields.size() == 1 && fields.get(0) instanceof Asn1OctetStringItem) {
                result = fields.get(0).encode();
            } else {
                throw new RuntimeException("Primitive encoding of " + Asn1TagNumber.OCTET_STRING.toString() + " must only contain exactly one child of type Asn1OctetStringItem!");
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
