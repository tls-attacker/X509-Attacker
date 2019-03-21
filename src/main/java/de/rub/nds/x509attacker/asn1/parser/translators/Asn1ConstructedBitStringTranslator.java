package de.rub.nds.x509attacker.asn1.parser.translators;

import de.rub.nds.x509attacker.asn1.model.Asn1BitString;
import de.rub.nds.x509attacker.asn1.model.Asn1Field;
import de.rub.nds.x509attacker.asn1.parser.ContentDecoderLookupTable;
import de.rub.nds.x509attacker.asn1.parser.StructureParser;

import java.util.List;

public class Asn1ConstructedBitStringTranslator extends Translator {

    public static final ContentDecoderLookupTable.Identifier IDENTIFIER = new ContentDecoderLookupTable.Identifier(
            Asn1BitString.TYPE_TAG_CLASS.getIntValue(),
            Asn1BitString.TYPE_IS_CONSTRUCTED,
            Asn1BitString.TYPE_TAG_NUMBER.getIntValue()
    );

    @Override
    public Asn1Field translatePrototype(final StructureParser.FieldPrototype fieldPrototype, final StructureParser.FieldPrototype parentPrototype) {
        Asn1BitString bitString = new Asn1BitString();
        bitString.setAsn1TagClass(fieldPrototype.tagClass.toString());
        bitString.setAsn1IsConstructed(fieldPrototype.isConstructed);
        bitString.setAsn1TagNumber(fieldPrototype.tagNumber);
        bitString.setAsn1Length(fieldPrototype.length);
        this.createChildFields(bitString, fieldPrototype);
        return bitString;
    }

    private void createChildFields(final Asn1BitString bitString, final StructureParser.FieldPrototype fieldPrototype) {
        List<StructureParser.FieldPrototype> children = fieldPrototype.parsedChildren;
        if (children != null) {
            for (StructureParser.FieldPrototype childPrototype : children) {
                Translator translator = ContentDecoderLookupTable.findTranslator(childPrototype);
                Asn1Field childField = translator.translatePrototype(childPrototype, fieldPrototype);
                bitString.addField(childField);
            }
        }
    }

    @Override
    public byte[] decodeContent(final byte[] content) {
        return content;
    }
}
