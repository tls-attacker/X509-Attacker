package de.rub.nds.asn1.parser;

import de.rub.nds.asn1.TagClass;
import de.rub.nds.asn1.TagConstructed;

import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;

public class SimpleFieldParser extends Parser {

    private static final int TAG_NUMBER_MASK = 0x1F;

    private static final int TAG_NUMBER_MORE = 0x80;

    private static final int TAG_NUMBER_CONTINUOUS_MASK = 0x7F;

    private static final int TAG_NUMBER_LONG_FORM = 0x1F;

    private static final int LENGTH_MSB_MASK = 0x80;

    private static final int LENGTH_RESERVED = 0xFF;

    private static final int LENGTH_INDEFINITE = 0x80;

    private static final int LENGTH_NUM_OCTETS_MASK = 0x7F;

    public SimpleFieldParser(final byte[] bytes) {
        super(bytes);
    }

    /**
     * Parses a single IntermediateAsn1Field and returns the result as a list.
     *
     * @return The resulting list containing the parsed IntermediateAsn1Field.
     * @throws ParserException
     */
    @Override
    public List<IntermediateAsn1Field> parse() throws ParserException {
        List<IntermediateAsn1Field> intermediateAsn1Fields = new LinkedList<>();
        IntermediateAsn1Field intermediateAsn1Field = this.parseAsn1Field();
        intermediateAsn1Fields.add(intermediateAsn1Field);
        return intermediateAsn1Fields;
    }

    /**
     * Parses and returns a single IntermediateAsn1Field.
     *
     * @return The parsed IntermediateAsn1Field.
     * @throws ParserException
     */
    protected IntermediateAsn1Field parseAsn1Field() throws ParserException {
        IntermediateAsn1Field intermediateAsn1Field = new IntermediateAsn1Field();
        this.parseIdentifier(intermediateAsn1Field);
        BigInteger length = this.parseLengthBytes(intermediateAsn1Field);
        this.parseContent(intermediateAsn1Field, length);
        return intermediateAsn1Field;
    }

    private void parseIdentifier(final IntermediateAsn1Field intermediateAsn1Field) throws ParserException {
        byte firstIdentifierByte = readByte();
        TagClass tagClass = TagClass.fromIdentifierByte(firstIdentifierByte);
        TagConstructed tagConstructed = TagConstructed.fromIdentifierByte(firstIdentifierByte);
        int tagNumber = this.parseTagNumber(firstIdentifierByte);
        intermediateAsn1Field.setTagClass(tagClass.getIntValue());
        intermediateAsn1Field.setConstructed(tagConstructed.getBooleanValue());
        intermediateAsn1Field.setTagNumber(tagNumber);
    }

    private int parseTagNumber(byte firstTagNumberByte) throws ParserException {
        int result = 0;
        if ((firstTagNumberByte & TAG_NUMBER_MASK) == TAG_NUMBER_LONG_FORM) {
            result = this.parseLongTagNumber();
        } else {
            result = (firstTagNumberByte & TAG_NUMBER_MASK);
        }
        return result;
    }

    private int parseLongTagNumber() throws ParserException {
        int result = 0;
        boolean more = true;
        while (more == true) {
            byte currentTagNumberByte = readByte();
            result = result << 7 | (currentTagNumberByte & TAG_NUMBER_CONTINUOUS_MASK);
            more = (currentTagNumberByte & TAG_NUMBER_MORE) != 0;
        }
        return result;
    }

    private BigInteger parseLengthBytes(final IntermediateAsn1Field intermediateAsn1Field) throws ParserException {
        BigInteger length = BigInteger.ZERO;
        byte firstLengthByte = readByte();
        if (firstLengthByte == LENGTH_RESERVED) {
            throw new ParserException("Length cannot be parsed since the first length byte has a reserved value!");
        } else if (firstLengthByte == LENGTH_INDEFINITE) {
            throw new ParserException("Length cannot be parsed since indefinite lengths are not supported yet! :(");
        } else {
            if ((firstLengthByte & LENGTH_MSB_MASK) == 0) {
                length = new BigInteger(new byte[]{firstLengthByte});
            } else {
                int numLengthOctets = firstLengthByte & LENGTH_NUM_OCTETS_MASK;
                byte[] lengthOctets = readBytes(numLengthOctets);
                length = new BigInteger(1, lengthOctets);
            }
        }
        intermediateAsn1Field.setLength(length);
        return length;
    }

    private void parseContent(final IntermediateAsn1Field intermediateAsn1Field, final BigInteger length) throws ParserException {
        int lengthValue = length.intValue();
        byte[] content = readBytes(lengthValue);
        intermediateAsn1Field.setContent(content);
    }
}
