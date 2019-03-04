package de.rub.nds.x509attacker.asn1.model;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagClass;
import de.rub.nds.x509attacker.asn1.fieldenums.Asn1TagNumber;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class Asn1ObjectIdentifier extends Asn1Field {

    private static final String DEFAULT_OBJECT_IDENTIFIER_VALUE = "";

    @XmlElement
    private String asn1ObjectIdentifierValue = DEFAULT_OBJECT_IDENTIFIER_VALUE;

    @XmlElement
    private ModifiableString asn1ObjectIdentifierValueModification;

    public Asn1ObjectIdentifier() {
        super();
        this.asn1ObjectIdentifierValueModification = new ModifiableString();
    }

    public String getAsn1ObjectIdentifierValue() {
        return asn1ObjectIdentifierValue;
    }

    public void setAsn1ObjectIdentifierValue(String asn1ObjectIdentifierValue) {
        this.asn1ObjectIdentifierValue = asn1ObjectIdentifierValue;
    }

    public ModifiableString getAsn1ObjectIdentifierValueModification() {
        return asn1ObjectIdentifierValueModification;
    }

    public void setAsn1ObjectIdentifierValueModification(ModifiableString asn1ObjectIdentifierValueModification) {
        this.asn1ObjectIdentifierValueModification = asn1ObjectIdentifierValueModification;
    }

    @Override
    protected void encodeForParentLayer() {
        this.updateDefaultValues();
        byte[] content = this.createContentBytes();
        super.setAsn1TagClass(Asn1TagClass.UNIVERSAL.toString());
        super.setAsn1IsConstructed(false);
        super.setAsn1TagNumber(Asn1TagNumber.OBJECT_IDENTIFIER.getIntValue());
        super.setAsn1Content(content);
        super.encodeForParentLayer();
    }

    private void updateDefaultValues() {
        if (this.asn1ObjectIdentifierValueModification.getOriginalValue() == null) {
            this.asn1ObjectIdentifierValueModification = ModifiableVariableFactory.safelySetValue(this.asn1ObjectIdentifierValueModification, this.asn1ObjectIdentifierValue);
        }
    }

    private byte[] createContentBytes() {
        byte[] content = null;
        String fullIdentifierString = this.asn1ObjectIdentifierValueModification.getValue().trim();
        String[] identifierStrings = fullIdentifierString.split("\\.");
        if (identifierStrings.length >= 2) {
            byte[][] encodedIdentifiers = this.encodeIdentifierStrings(identifierStrings);
            int totalLength = 0;
            int contentPos = 0;
            for (int i = 0; i < encodedIdentifiers.length; i++) {
                totalLength += encodedIdentifiers[i].length;
            }
            content = new byte[totalLength];
            for (int i = 0; i < encodedIdentifiers.length; i++) {
                for (int j = 0; j < encodedIdentifiers[i].length; j++) {
                    content[contentPos] = encodedIdentifiers[i][j];
                    contentPos++;
                }
            }
        } else {
            content = new byte[0];
        }
        return content;
    }

    private byte[][] encodeIdentifierStrings(String[] identifierStrings) {
        byte[][] encodedIdentifiers = new byte[identifierStrings.length - 1][];
        encodedIdentifiers[0] = this.encodeFirstTwoIdentifierStrings(identifierStrings);
        for (int i = 1; i < encodedIdentifiers.length; i++) {
            int identifierValue = Integer.parseInt(identifierStrings[i + 1]);
            encodedIdentifiers[i] = this.encodeSingleIdentifier(identifierValue);
        }
        return encodedIdentifiers;
    }

    private byte[] encodeFirstTwoIdentifierStrings(String[] identifierStrings) {
        int identifier1 = Integer.parseInt(identifierStrings[0]);
        int identifier2 = Integer.parseInt(identifierStrings[1]);
        return new byte[]{(byte) (identifier1 * 40 + identifier2)};
    }

    private byte[] encodeSingleIdentifier(int identifierValue) {
        int numberOfIdentifierValueBytes = this.computeNumberOfIdentifierValueBytes(identifierValue);
        byte[] encodedIdentifier = new byte[numberOfIdentifierValueBytes];
        byte moreFlag = 0x00;
        for (int i = numberOfIdentifierValueBytes - 1; i >= 0; i--) {
            encodedIdentifier[i] = (byte) (moreFlag | (identifierValue & 0x7F));
            identifierValue = identifierValue >> 7;
            moreFlag = (byte) 0x80;
        }
        return encodedIdentifier;
    }

    private int computeNumberOfIdentifierValueBytes(int identifierValue) {
        int numberOfIdentifierValueBytes = 1;
        identifierValue = identifierValue >> 7;
        while (identifierValue > 0) {
            numberOfIdentifierValueBytes++;
            identifierValue = identifierValue >> 7;
        }
        return numberOfIdentifierValueBytes;
    }
}
