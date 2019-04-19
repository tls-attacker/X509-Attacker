package de.rub.nds.asn1.parser;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.LinkedList;
import java.util.List;

public class StructureParser extends SimpleFieldParser {

    private static final Logger LOGGER = LogManager.getLogger();

    public StructureParser(final byte[] bytes) {
        super(bytes);
    }

    @Override
    public List<IntermediateAsn1Field> parse() throws ParserException {
        List<IntermediateAsn1Field> intermediateAsn1Fields = this.parseAllAsn1Fields();
        return intermediateAsn1Fields;
    }

    protected List<IntermediateAsn1Field> parseAllAsn1Fields() throws ParserException {
        List<IntermediateAsn1Field> intermediateAsn1Fields = new LinkedList<>();
        while(this.getNumberOfRemainingBytes() > 0) {
            IntermediateAsn1Field intermediateAsn1Field = this.parseAsn1Field();
            ContentDescriptorTable.ContentDescriptor contentDescriptor = this.getContentDescriptor(intermediateAsn1Field);
            intermediateAsn1Field.setChildren(this.parseChildren(intermediateAsn1Field, contentDescriptor));
            intermediateAsn1Fields.add(intermediateAsn1Field);
        }
        return intermediateAsn1Fields;
    }

    private ContentDescriptorTable.ContentDescriptor getContentDescriptor(final IntermediateAsn1Field intermediateAsn1Field) {
        int tagClass = intermediateAsn1Field.getTagClass();
        boolean isConstructed = intermediateAsn1Field.isConstructed();
        int tagNumber = intermediateAsn1Field.getTagNumber();
        return ContentDescriptorTable.getContentDescriptorForIdentifier(tagClass, isConstructed, tagNumber);
    }

    private List<IntermediateAsn1Field> parseChildren(final IntermediateAsn1Field intermediateAsn1Field, final ContentDescriptorTable.ContentDescriptor contentDescriptor) throws ParserException {
        List<IntermediateAsn1Field> children = new LinkedList<>();
        if(contentDescriptor.contentUnpacker != null) {
            byte[] unpackedContent = contentDescriptor.contentUnpacker.unpack(intermediateAsn1Field.getContent());
            StructureParser childrenStructureParser = new StructureParser(unpackedContent);
            try {
                children = childrenStructureParser.parse();
            }
            catch(ParserException e) {
                if(contentDescriptor.mustContainValidChildren == true) {
                    LOGGER.error("Field must contain valid children, but an exception occurred when parsing the field's children!");
                    throw e;
                }
                else {
                    LOGGER.info("Ignoring parser exception during decoding of a field's children since the field does not need to contain valid children.");
                }
            }
        }
        else {
            throw new ParserException("Cannot parse children of a field if not content decoder is specified in the field's content descriptor!");
        }
        return children;
    }
}
