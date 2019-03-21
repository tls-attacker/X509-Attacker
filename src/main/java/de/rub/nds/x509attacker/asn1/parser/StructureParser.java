package de.rub.nds.x509attacker.asn1.parser;

import de.rub.nds.x509attacker.asn1.Asn1TagClass;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.LinkedList;
import java.util.List;

public class StructureParser extends Parser<List<StructureParser.FieldPrototype>> {

    static final byte TAG_CLASS_MASK = (byte) 0xC0;
    static final byte IS_CONSTRUCTED_MASK = (byte) 0x20;
    static final byte TAG_NUMBER_MASK = (byte) 0x1F;
    static final byte TAG_NUMBER_MORE_MASK = (byte) 0x80;
    static final byte TAG_NUMBER_LONG_MASK = (byte) 0x7F;
    static final byte LENGTH_MSB_MASK = (byte) 0x80;
    private static final Logger LOGGER = LogManager.getLogger();

    public StructureParser(byte[] asn1Bytes) {
        super(0, asn1Bytes);
    }

    public List<FieldPrototype> parse() {
        List<FieldPrototype> resultList = new LinkedList<>();
        try {
            while (this.getBytesLeft() > 0) {
                resultList.add(this.parseNextField());
            }
        } catch (ParserException e) {
            LOGGER.info("Ignoring ParserException (" + e.getMessage() + ").");
            resultList.clear();
        }
        this.createAndExecuteAllContentParsers(resultList);
        return resultList;
    }

    private FieldPrototype parseNextField() throws ParserException {
        FieldPrototype prototype = new FieldPrototype();
        this.parseIdentifierBytes(prototype);
        this.parseLengthBytes(prototype);
        this.parseContentBytes(prototype);
        return prototype;
    }

    private void parseIdentifierBytes(FieldPrototype prototype) throws ParserException {
        byte firstIdentifierByte = this.parseByteField(1);
        byte tagClassByte = (byte) ((firstIdentifierByte & TAG_CLASS_MASK & 0xFF) >> 6);
        byte isConstructedByte = (byte) (firstIdentifierByte & IS_CONSTRUCTED_MASK);
        byte tagNumberByte = (byte) (firstIdentifierByte & TAG_NUMBER_MASK);
        prototype.tagClass = Asn1TagClass.fromByte(tagClassByte);
        prototype.isConstructed = isConstructedByte != 0;
        prototype.tagNumber = this.parseTagNumber(tagNumberByte);
    }

    private int parseTagNumber(byte tagNumberByte) throws ParserException {
        int tagNumber = 0;
        if (tagNumberByte == 0x1F) {
            byte nextTagNumberByte, more;
            do {
                nextTagNumberByte = this.parseByteField(1);
                more = (byte) (nextTagNumberByte & TAG_NUMBER_MORE_MASK & 0xFF);
                nextTagNumberByte = (byte) (nextTagNumberByte & TAG_NUMBER_LONG_MASK & 0xFF);
                tagNumber = (tagNumber << 7) | nextTagNumberByte;
            } while (more != 0);
        } else {
            tagNumber = tagNumberByte;
        }
        return tagNumber;
    }

    private void parseLengthBytes(FieldPrototype prototype) throws ParserException {
        int length = 0;
        byte firstLengthByte = this.parseByteField(1);
        if ((firstLengthByte & LENGTH_MSB_MASK) == 0) {
            length = firstLengthByte;
        } else {
            byte numberOfLengthBytes = (byte) (firstLengthByte & ~LENGTH_MSB_MASK & 0xFF);
            if (numberOfLengthBytes == 0) {
                length = FieldPrototype.INDEFINTE_LENGTH;
            } else if (numberOfLengthBytes == 127) {
                throw new ParserException("Length byte indicates use of a reserved length type which is not allowed!");
            } else {
                for (int i = 0; i < numberOfLengthBytes; i++) {
                    length = (length << 8) | (this.parseByteField(1) & 0xFF);
                }
            }
        }
        prototype.length = length;
    }

    private void parseContentBytes(FieldPrototype prototype) throws ParserException {
        byte[] content = null;
        if (prototype.length == FieldPrototype.INDEFINTE_LENGTH) {
            // Todo: Maybe add support for indefinite lengths. However, that might not be needed since certificates don't use indefinite lengths.
            throw new ParserException("Reading of content octets with indefinite length is not supported yet!");
        } else {
            content = this.parseByteArrayField(prototype.length);
        }
        prototype.content = content;
    }

    private void createAndExecuteAllContentParsers(List<FieldPrototype> fieldPrototypes) {
        for (FieldPrototype prototype : fieldPrototypes) {
            this.createAndExecuteContentParser(prototype);
        }
    }

    private void createAndExecuteContentParser(FieldPrototype fieldPrototype) {
        byte[] content = this.getDecodedContent(fieldPrototype);
        StructureParser prototypeParser = new StructureParser(content);
        List<FieldPrototype> prototypeChildren = prototypeParser.parse();
        for (FieldPrototype child : prototypeChildren) {
            fieldPrototype.parsedChildren.add(child);
        }
    }

    private byte[] getDecodedContent(FieldPrototype fieldPrototype) {
        ContentDecoderLookupTable.Identifier identifier = new ContentDecoderLookupTable.Identifier(
                fieldPrototype.tagClass.getIntValue(),
                fieldPrototype.isConstructed,
                fieldPrototype.tagNumber
        );
        ContentDecoderLookupTable.DecodeTableEntry decodeTableEntry = ContentDecoderLookupTable.findEntry(identifier);
        return decodeTableEntry.translator.decodeContent(fieldPrototype.content);
    }

    public class FieldPrototype {
        public static final int INDEFINTE_LENGTH = -1;
        public final List<FieldPrototype> parsedChildren = new LinkedList<>();
        public Asn1TagClass tagClass = null;
        public boolean isConstructed = false;
        public int tagNumber = 0;
        public int length = 0;
        public byte[] content = null;
    }
}
