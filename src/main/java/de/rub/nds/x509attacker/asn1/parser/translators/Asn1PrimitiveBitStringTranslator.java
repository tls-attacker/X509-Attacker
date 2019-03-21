package de.rub.nds.x509attacker.asn1.parser.translators;

import de.rub.nds.x509attacker.asn1.model.Asn1BitString;
import de.rub.nds.x509attacker.asn1.model.Asn1Field;
import de.rub.nds.x509attacker.asn1.parser.ContentDecoderLookupTable;
import de.rub.nds.x509attacker.asn1.parser.StructureParser;

import java.util.List;

public class Asn1PrimitiveBitStringTranslator extends Translator {

    public static final ContentDecoderLookupTable.Identifier IDENTIFIER = new ContentDecoderLookupTable.Identifier(
            Asn1BitString.Asn1BitStringItem.TYPE_TAG_CLASS.getIntValue(),
            Asn1BitString.Asn1BitStringItem.TYPE_IS_CONSTRUCTED,
            Asn1BitString.Asn1BitStringItem.TYPE_TAG_NUMBER.getIntValue()
    );

    @Override
    public Asn1Field translatePrototype(final StructureParser.FieldPrototype fieldPrototype, final StructureParser.FieldPrototype parentPrototype) {
        Asn1BitString.Asn1BitStringItem bitStringItem = null;
        if (fieldPrototype.parsedChildren != null && fieldPrototype.parsedChildren.size() > 0) {
            bitStringItem = this.createAsn1EncapsulatingBitStringItem(fieldPrototype);
        } else {
            bitStringItem = this.createAsn1BitStringItem(fieldPrototype);
        }
        return this.createWrapperIfNecessary(bitStringItem, parentPrototype);
    }

    private Asn1BitString.Asn1BitStringItem createAsn1BitStringItem(final StructureParser.FieldPrototype fieldPrototype) {
        Asn1BitString.Asn1BitStringItem bitStringItem = new Asn1BitString.Asn1BitStringItem();
        bitStringItem.setAsn1TagClass(fieldPrototype.tagClass.toString());
        bitStringItem.setAsn1IsConstructed(fieldPrototype.isConstructed);
        bitStringItem.setAsn1TagNumber(fieldPrototype.tagNumber);
        bitStringItem.setAsn1Length(fieldPrototype.length);
        bitStringItem.setAsn1NumberOfUnusedBits(fieldPrototype.content[0]);
        bitStringItem.setAsn1BitStringValue(this.decodeContent(fieldPrototype.content));
        return bitStringItem;
    }

    private Asn1BitString.Asn1EncapsulatingBitStringItem createAsn1EncapsulatingBitStringItem(final StructureParser.FieldPrototype fieldPrototype) {
        Asn1BitString.Asn1EncapsulatingBitStringItem bitStringItem = new Asn1BitString.Asn1EncapsulatingBitStringItem();
        bitStringItem.setAsn1TagClass(fieldPrototype.tagClass.toString());
        bitStringItem.setAsn1IsConstructed(fieldPrototype.isConstructed);
        bitStringItem.setAsn1TagNumber(fieldPrototype.tagNumber);
        bitStringItem.setAsn1Length(fieldPrototype.length);
        this.createChildFields(bitStringItem, fieldPrototype);
        return bitStringItem;
    }

    private void createChildFields(final Asn1BitString.Asn1EncapsulatingBitStringItem bitStringItem, final StructureParser.FieldPrototype fieldPrototype) {
        List<StructureParser.FieldPrototype> children = fieldPrototype.parsedChildren;
        if (children != null) {
            for (StructureParser.FieldPrototype childPrototype : children) {
                Translator translator = ContentDecoderLookupTable.findTranslator(childPrototype);
                Asn1Field childField = translator.translatePrototype(childPrototype, fieldPrototype);
                bitStringItem.addField(childField);
            }
        }
    }

    private Asn1Field createWrapperIfNecessary(Asn1BitString.Asn1BitStringItem bitStringItem, final StructureParser.FieldPrototype parentPrototype) {
        Asn1Field returnField = bitStringItem;
        ContentDecoderLookupTable.Identifier constructedBitStringIdentifier = new ContentDecoderLookupTable.Identifier(
                Asn1BitString.TYPE_TAG_CLASS.getIntValue(),
                Asn1BitString.TYPE_IS_CONSTRUCTED,
                Asn1BitString.TYPE_TAG_NUMBER.getIntValue()
        );
        if (ContentDecoderLookupTable.Identifier.fromFieldPrototype(parentPrototype).equals(constructedBitStringIdentifier) == false) {
            Asn1BitString bitString = new Asn1BitString();
            bitString.addField(bitStringItem);
            returnField = bitString;
        }
        return returnField;
    }

    @Override
    public byte[] decodeContent(final byte[] content) {
        byte[] result = new byte[0];
        if (content != null && content.length > 1) {
            result = new byte[content.length - 1];
            System.arraycopy(content, 1, result, 0, content.length - 1);
        }
        return result;
    }
}
