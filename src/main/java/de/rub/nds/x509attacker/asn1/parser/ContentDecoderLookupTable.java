package de.rub.nds.x509attacker.asn1.parser;

import de.rub.nds.x509attacker.asn1.parser.translators.Asn1AnonymousFieldTranslator;
import de.rub.nds.x509attacker.asn1.parser.translators.Asn1ConstructedBitStringTranslator;
import de.rub.nds.x509attacker.asn1.parser.translators.Asn1PrimitiveBitStringTranslator;
import de.rub.nds.x509attacker.asn1.parser.translators.Translator;

public class ContentDecoderLookupTable {

    public static final DecodeTableEntry FALLBACK_ENTRY = new DecodeTableEntry(null, new Asn1AnonymousFieldTranslator(), true);

    private static DecodeTableEntry[] decodeTable = new DecodeTableEntry[]{
            FALLBACK_ENTRY,
            new DecodeTableEntry(Asn1ConstructedBitStringTranslator.IDENTIFIER, new Asn1ConstructedBitStringTranslator(), true),
            new DecodeTableEntry(Asn1PrimitiveBitStringTranslator.IDENTIFIER, new Asn1PrimitiveBitStringTranslator(), true),
    };

    /**
     * Performs a lookup with the specified identifier.
     *
     * @param identifier The identifier that is looked for.
     * @return The decode table entry. If no entry was found, the FALLBACK_ENTRY is returned.
     */
    public static DecodeTableEntry findEntry(final Identifier identifier) {
        DecodeTableEntry result = null;
        for (DecodeTableEntry currentEntry : decodeTable) {
            if (currentEntry.identifier != null && currentEntry.identifier.equals(identifier)) {
                result = currentEntry;
                break;
            }
        }
        if (result == null) {
            result = FALLBACK_ENTRY;
        }
        return result;
    }

    public static Translator findTranslator(final StructureParser.FieldPrototype fieldPrototype) {
        Identifier identifier = Identifier.fromFieldPrototype(fieldPrototype);
        ContentDecoderLookupTable.DecodeTableEntry decodeTableEntry = ContentDecoderLookupTable.findEntry(identifier);
        return decodeTableEntry.translator;
    }

    /**
     * A tupel to group information for a single entry in the decoder table.
     */
    public static class DecodeTableEntry {

        public final Identifier identifier;

        public final Translator translator;

        public final boolean tryToInterpretContent;

        public DecodeTableEntry(final Identifier identifier, final Translator translator, final boolean tryToInterpretContent) {
            this.identifier = identifier;
            this.translator = translator;
            this.tryToInterpretContent = tryToInterpretContent;
        }
    }

    /**
     * The Identifier class groups the three identifier properties tagClass, isConstructed, and tagNumber. Identifier
     * instances can be compared using the equals method.
     */
    public static class Identifier {

        public final int tagClass;

        public final boolean isConstructed;

        public final int tagNumber;

        public Identifier(final int tagClass, final boolean isConstructed, final int tagNumber) {
            this.tagClass = tagClass;
            this.isConstructed = isConstructed;
            this.tagNumber = tagNumber;
        }

        public static Identifier fromFieldPrototype(StructureParser.FieldPrototype fieldPrototype) {
            return new Identifier(
                    fieldPrototype.tagClass.getIntValue(),
                    fieldPrototype.isConstructed,
                    fieldPrototype.tagNumber
            );
        }

        /**
         * Compares this instance to another Object.
         *
         * @param obj The other object.
         * @return True, if the other object is of type Identifier and tagclass, isConstructed, and tagNumber match.
         */
        @Override
        public boolean equals(Object obj) {
            boolean equals = false;
            if (obj instanceof Identifier) {
                Identifier identifier = (Identifier) obj;
                boolean isTagClassEqual = this.tagClass == identifier.tagClass;
                boolean isIsConstructedEqual = this.isConstructed == identifier.isConstructed;
                boolean isTagNumberEqual = this.tagNumber == identifier.tagNumber;
                if (isTagClassEqual && isIsConstructedEqual && isTagNumberEqual) {
                    equals = true;
                }
            }
            return equals;
        }
    }
}
