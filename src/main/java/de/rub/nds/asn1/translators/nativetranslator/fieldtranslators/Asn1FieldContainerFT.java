package de.rub.nds.asn1.translators.nativetranslator.fieldtranslators;

import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.model.Asn1FieldContainer;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;

import java.util.List;

public class Asn1FieldContainerFT extends Asn1FieldFT {

    /**
     * Translates an IntermediateAsn1Field into an Asn1Field since Asn1FieldContainer cannot be instantiated.
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

    protected void translateAsn1FieldContainer(final IntermediateAsn1Field intermediateAsn1Field, final Asn1FieldContainer asn1FieldContainer) {
        List<IntermediateAsn1Field> children = intermediateAsn1Field.getChildren();
        for(IntermediateAsn1Field childIntermediateAsn1Field : children) {

        }
    }
}
