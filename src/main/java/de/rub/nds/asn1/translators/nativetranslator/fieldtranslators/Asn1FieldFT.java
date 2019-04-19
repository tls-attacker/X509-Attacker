package de.rub.nds.asn1.translators.nativetranslator.fieldtranslators;

import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;

public class Asn1FieldFT extends FieldTranslator {

    /**
     * Translates an IntermediateAsn1Field into an Asn1Field.
     *
     * @param intermediateAsn1Field The IntermediateAsn1Field to be translated.
     * @return The translated Asn1Field.
     */
    @Override
    public Asn1Field translateImmediateAsn1Field(final IntermediateAsn1Field intermediateAsn1Field) {
        Asn1Field asn1Field = new Asn1Field();
        this.translateAsn1Field(intermediateAsn1Field, asn1Field);
        return asn1Field;
    }

    /**
     * Updates an Asn1Field's values with the given instance of IntermediateAsn1Field.
     *
     * @param intermediateAsn1Field A given instance of IntermediateAsn1Field to extract values from.
     * @param asn1Field          The Asn1Field which will be updated.
     */
    protected void translateAsn1Field(final IntermediateAsn1Field intermediateAsn1Field, final Asn1Field asn1Field) {
        asn1Field.setTagClass(intermediateAsn1Field.getTagClass());
        asn1Field.setConstructed(intermediateAsn1Field.isConstructed());
        asn1Field.setTagNumber(intermediateAsn1Field.getTagNumber());
        asn1Field.setContent(intermediateAsn1Field.getContent());
    }
}
