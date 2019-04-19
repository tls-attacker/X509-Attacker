package de.rub.nds.asn1.translators.typetranslators;

import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;

public class Asn1FieldTranslator implements TypeTranslator {

    private final IntermediateAsn1Field intermediateAsn1Field;

    private final Asn1Field asn1Field;

    public Asn1FieldTranslator(final IntermediateAsn1Field intermediateAsn1Field) {
        this(intermediateAsn1Field, new Asn1Field());
    }

    protected Asn1FieldTranslator(final IntermediateAsn1Field intermediateAsn1Field, final Asn1Field asn1Field) {
        this.intermediateAsn1Field = intermediateAsn1Field;
        this.asn1Field = asn1Field;
    }

    @Override
    public Asn1Field translate() {
        this.asn1Field.setTagClass(this.intermediateAsn1Field.getTagClass());
        this.asn1Field.setConstructed(this.intermediateAsn1Field.isConstructed());
        this.asn1Field.setTagNumber(this.intermediateAsn1Field.getTagNumber());
        this.asn1Field.setLength(this.intermediateAsn1Field.getLength());
        this.asn1Field.setContent(this.intermediateAsn1Field.getContent());
        return this.asn1Field;
    }
}
