package de.rub.nds.asn1.encoder;

import de.rub.nds.asn1.model.Asn1Field;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;

public class Asn1FieldEncoder extends Asn1Encoder {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Asn1Field field;

    public Asn1FieldEncoder(Asn1Field field) {
        this.field = field;
    }

    @Override
    public byte[] encode() {
        this.updateModifiableVariables();
        byte[] identifier = this.encodeIdentifier();
        byte[] content = this.encodeContent();
        byte[] length = this.encodeLength(BigInteger.valueOf(content.length));
        return merge(identifier, length, content);
    }

    @Override
    public Asn1Field encodeAndGetAsn1Field() {
        this.encode();
        return this.field;
    }

    private final void updateModifiableVariables() {
        int tagClass = this.field.getTagClass();
        boolean isConstructed = this.field.isConstructed();
        int tagNumber = this.field.getTagNumber();
        BigInteger length = this.field.getLength();
        byte[] content = this.field.getContent();
        this.field.setTagClassModificationValue(tagClass);
        this.field.setIsConstructedModificationValue(isConstructed);
        this.field.setTagNumberModificationValue(tagNumber);
        this.field.setLengthModificationValue(length);
        this.field.setContentModificationValue(content);
    }

    private final byte[] encodeIdentifier() {
        byte firstIdentifierByte = 0;
        firstIdentifierByte = this.encodeTagClass(firstIdentifierByte, this.field.getFinalTagClass());
        firstIdentifierByte = this.encodeIsConstructed(firstIdentifierByte, this.field.getFinalIsConstructed());
        return this.encodeTagNumber(firstIdentifierByte, this.field.getFinalTagNumber());
    }

    private byte encodeTagClass(byte firstIdentifierByte, int tagClass) {
        return (byte) (firstIdentifierByte | ((tagClass & 0x3) << 6));
    }

    private byte encodeIsConstructed(byte firstIdentifierByte, boolean isConstructed) {
        return ((isConstructed == true) ? (byte) (firstIdentifierByte | 0x20) : firstIdentifierByte);
    }

    private byte[] encodeTagNumber(byte firstIdentifierByte, int tagNumber) {
        byte[] result = null;
        if(tagNumber < 0) {
            LOGGER.warn("Tag number is smaller than zero. Defaulting to zero!");
            tagNumber = 0;
        }
        if(tagNumber <= 0x1F) {
            result = new byte[] { firstIdentifierByte };
            result[0] |= (byte) (tagNumber & 0x1F);
        }
        else {
            byte[] longEncoding = this.encodeLongTagNumber(firstIdentifierByte, tagNumber);
            firstIdentifierByte = (byte) (firstIdentifierByte | 0x1F);
            result = merge(new byte[] { firstIdentifierByte }, longEncoding);
        }
        return result;
    }

    private byte[] encodeLongTagNumber(byte firstIdentifierByte, int tagNumber) {
        int tagNumberByteCount = this.getTagNumberByteCount(tagNumber);
        byte[] result = new byte[tagNumberByteCount];
        byte moreFlag = 0x00;
        for(int i = tagNumberByteCount - 1; i >= 0; i--) {
            result[i] = (byte) (moreFlag | (tagNumber & 0x7F));
            tagNumber = tagNumber >> 7;
            moreFlag = (byte) 0x80;
        }
        return result;
    }

    private int getTagNumberByteCount(int tagNumber) {
        int result = 0;
        while(tagNumber > 0) {
            result++;
            tagNumber = tagNumber >> 7;
        }
        return result;
    }

    private final byte[] encodeLength(BigInteger contentLength) {
        byte[] result = null;
        this.field.setLengthModificationValue(contentLength);
        BigInteger length = this.field.getFinalLength();
        if(length.compareTo(BigInteger.ZERO) == -1) {
            LOGGER.warn("Field length is smaller than zero. Defaulting to zero!");
            length = BigInteger.ZERO;
        }
        if(length.compareTo(BigInteger.valueOf(127)) <= 0) {
            result = new byte[] { (byte) length.byteValue() };
        }
        else {
            result = encodeLongLength(length);
        }
        return result;
    }

    private byte[] encodeLongLength(BigInteger length) {
        byte[] result = null;
        byte[] longLength = length.toByteArray();
        if(longLength[0] == 0x00) {
            longLength[0] = (byte) (0x80 | longLength.length - 1);
            result = longLength;
        }
        else {
            byte[] prefix = new byte[] { (byte) (0x80 | longLength.length) };
            result = merge(prefix, longLength);
        }
        return result;
    }

    private final byte[] encodeContent() {
        return field.getContentModification().getValue();
    }
}
