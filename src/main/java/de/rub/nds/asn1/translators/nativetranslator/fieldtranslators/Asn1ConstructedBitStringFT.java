package de.rub.nds.asn1.translators.nativetranslator.fieldtranslators;

import de.rub.nds.asn1.model.Asn1ConstructedBitString;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;

public class Asn1ConstructedBitStringFT extends Asn1FieldContainerFT {

    /**
     * Translates an IntermediateAsn1Field into an Asn1ConstructedBitString.
     *
     * @param intermediateAsn1Field The IntermediateAsn1Field to be translated.
     * @return The translated Asn1ConstructedBitString.
     */
    @Override
    public Asn1ConstructedBitString translateImmediateAsn1Field(final IntermediateAsn1Field intermediateAsn1Field) {
        Asn1ConstructedBitString asn1ConstructedBitString = new Asn1ConstructedBitString();
        this.translateAsn1Boolean(intermediateAsn1Field, asn1ConstructedBitString);
        return asn1ConstructedBitString;
    }
}
