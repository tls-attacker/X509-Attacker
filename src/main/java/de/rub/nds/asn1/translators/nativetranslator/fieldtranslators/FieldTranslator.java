package de.rub.nds.asn1.translators.nativetranslator.fieldtranslators;

import de.rub.nds.asn1.TagClass;
import de.rub.nds.asn1.TagConstructed;
import de.rub.nds.asn1.TagNumber;
import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;

public abstract class FieldTranslator {

    private static FieldTranslator DEFAULT_FIELD_TRANSLATOR = new Asn1FieldFT();

    private static final FieldTranslatorTableEntry[] fieldTranslatorTableEntries = new FieldTranslatorTableEntry[]{
            new FieldTranslatorTableEntry(TagClass.UNIVERSAL, TagConstructed.PRIMITIVE, TagNumber.BOOLEAN, false, false, new Asn1BooleanFT()),
            new FieldTranslatorTableEntry(TagClass.UNIVERSAL, TagConstructed.CONSTRUCTED, TagNumber.BIT_STRING, true, true, null), // constructed bit string
            new FieldTranslatorTableEntry(TagClass.UNIVERSAL, TagConstructed.CONSTRUCTED, TagNumber.IA5STRING, true, true, null), // constructed ia5 string
            new FieldTranslatorTableEntry(TagClass.UNIVERSAL, TagConstructed.CONSTRUCTED, TagNumber.OCTET_STRING, true, true, null), // constructed octet string
            new FieldTranslatorTableEntry(TagClass.UNIVERSAL, TagConstructed.CONSTRUCTED, TagNumber.PRINTABLESTRING, true, true, null), // constructed printable string
            new FieldTranslatorTableEntry(TagClass.UNIVERSAL, TagConstructed.CONSTRUCTED, TagNumber.T61STRING, true, true, null), // constructed t61 string
            new FieldTranslatorTableEntry(TagClass.UNIVERSAL, TagConstructed.CONSTRUCTED, TagNumber.UTCTIME, true, true, null), // constructed utc time
            new FieldTranslatorTableEntry(TagClass.UNIVERSAL, TagConstructed.CONSTRUCTED, TagNumber.UTF8STRING, true, true, null), // constructed utf8 string
            new FieldTranslatorTableEntry(TagClass.UNIVERSAL, TagConstructed.PRIMITIVE, TagNumber.BIT_STRING, true, true, null), // encapsulating bit string
            new FieldTranslatorTableEntry(TagClass.UNIVERSAL, TagConstructed.PRIMITIVE, TagNumber.OCTET_STRING, true, true, null), // encapsulating octet string
            // explicit cannot be modelled
            // implicit cannot be modelled
            new FieldTranslatorTableEntry(TagClass.UNIVERSAL, TagConstructed.PRIMITIVE, TagNumber.INTEGER, false, false, null), // integer
            new FieldTranslatorTableEntry(TagClass.UNIVERSAL, TagConstructed.PRIMITIVE, TagNumber.NULL, false, false, null), // null
            new FieldTranslatorTableEntry(TagClass.UNIVERSAL, TagConstructed.PRIMITIVE, TagNumber.OBJECT_IDENTIFIER, false, false, null), // object identifier
            new FieldTranslatorTableEntry(TagClass.UNIVERSAL, TagConstructed.PRIMITIVE, TagNumber.BIT_STRING, true, false, null), // primitive bit string
            new FieldTranslatorTableEntry(TagClass.UNIVERSAL, TagConstructed.PRIMITIVE, TagNumber.IA5STRING, true, false, null), // primitive ia5 string
            new FieldTranslatorTableEntry(TagClass.UNIVERSAL, TagConstructed.PRIMITIVE, TagNumber.OCTET_STRING, true, false, null), // primitive octet string
            new FieldTranslatorTableEntry(TagClass.UNIVERSAL, TagConstructed.PRIMITIVE, TagNumber.PRINTABLESTRING, true, false, null), // primitive printable string
            new FieldTranslatorTableEntry(TagClass.UNIVERSAL, TagConstructed.PRIMITIVE, TagNumber.T61STRING, true, false, null), // primitive t61 string
            new FieldTranslatorTableEntry(TagClass.UNIVERSAL, TagConstructed.PRIMITIVE, TagNumber.UTCTIME, true, false, null), // primitive utc time
            new FieldTranslatorTableEntry(TagClass.UNIVERSAL, TagConstructed.PRIMITIVE, TagNumber.UTF8STRING, true, false, null), // primitive utf8 string
            new FieldTranslatorTableEntry(TagClass.UNIVERSAL, TagConstructed.CONSTRUCTED, TagNumber.SEQUENCE, true, true, null), // sequence
            new FieldTranslatorTableEntry(TagClass.UNIVERSAL, TagConstructed.CONSTRUCTED, TagNumber.SET, true, true, null), // set
    };

    private static class FieldTranslatorTableEntry {

        public final int tagClass;

        public final boolean isConstructed;

        public final int tagNumber;

        public final boolean mayHaveChildren;

        public final boolean hasChildren;

        public final FieldTranslator fieldTranslator;

        public FieldTranslatorTableEntry(final int tagClass, final boolean isConstructed, final int tagNumber, final boolean mayHaveChildren, final boolean hasChildren, final FieldTranslator fieldTranslator) {
            this.tagClass = tagClass;
            this.isConstructed = isConstructed;
            this.tagNumber = tagNumber;
            this.mayHaveChildren = mayHaveChildren;
            this.hasChildren = hasChildren;
            this.fieldTranslator = fieldTranslator;
        }

        public FieldTranslatorTableEntry(final TagClass tagClass, final TagConstructed tagConstructed, final TagNumber tagNumber, final boolean mayHaveChildren, final boolean hasChildren, final FieldTranslator fieldTranslator) {
            this(tagClass.getIntValue(), tagConstructed.getBooleanValue(), tagNumber.getIntValue(), mayHaveChildren, hasChildren, fieldTranslator);
        }

        @Override
        public boolean equals(Object object) {
            boolean result = true;
            if (object instanceof FieldTranslatorTableEntry) {
                FieldTranslatorTableEntry fieldTranslatorTableEntry = (FieldTranslatorTableEntry) object;
                boolean mayHaveChildren = this.mayHaveChildren | fieldTranslatorTableEntry.mayHaveChildren;
                if (this.tagClass != fieldTranslatorTableEntry.tagClass)
                    result = false;
                if (this.isConstructed != fieldTranslatorTableEntry.isConstructed)
                    result = false;
                if (this.tagNumber != fieldTranslatorTableEntry.tagNumber)
                    result = false;
                if (mayHaveChildren == true && this.hasChildren != fieldTranslatorTableEntry.hasChildren)
                    result = false;
            } else {
                result = false;
            }
            return result;
        }

        public static FieldTranslatorTableEntry fromIdentifierAndChildren(final int tagClass, final boolean isConstructed, final int tagNumber, final boolean hasChildren) {
            return new FieldTranslatorTableEntry(tagClass, isConstructed, tagNumber, false, hasChildren, null);
        }
    }

    /**
     * Translates an IntermediateAsn1Field into an Asn1Encodable.
     *
     * @param intermediateAsn1Field The IntermediateAsn1Field to be translated.
     * @return The translated Asn1Encodable.
     */
    public abstract Asn1Encodable translateImmediateAsn1Field(final IntermediateAsn1Field intermediateAsn1Field);

    public static FieldTranslator getFieldTranslator(final int tagClass, final boolean isConstructed, final int tagNumber, final boolean hasChildren) {
        FieldTranslator fieldTranslator = DEFAULT_FIELD_TRANSLATOR;
        FieldTranslatorTableEntry compareFieldTranslatorTableEntry = FieldTranslatorTableEntry.fromIdentifierAndChildren(tagClass, isConstructed, tagNumber, hasChildren);
        for (FieldTranslatorTableEntry fieldTranslatorTableEntry : fieldTranslatorTableEntries) {
            if (fieldTranslatorTableEntry.equals(compareFieldTranslatorTableEntry) == true) {
                fieldTranslator = fieldTranslatorTableEntry.fieldTranslator;
                break;
            }
        }
        return fieldTranslator;
    }
}
