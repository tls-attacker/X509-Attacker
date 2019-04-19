package de.rub.nds.asn1.translators.contextbasedtranslator;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translators.TranslatorException;
import de.rub.nds.asn1.translators.contextbasedtranslator.context.Context;
import de.rub.nds.asn1.translators.nativetranslator.fieldtranslators.FieldTranslator;
import de.rub.nds.asn1.translators.nativetranslator.NativeTranslator;

import java.util.LinkedList;
import java.util.List;

public class ContextBasedTranslator extends NativeTranslator {

    private final Context context;

    public ContextBasedTranslator(final Context context) {
        super();
        this.context = context;
    }

    @Override
    public List<Asn1Encodable> translate(final List<IntermediateAsn1Field> intermediateAsn1Fields) throws TranslatorException {
        List<Asn1Encodable> asn1Fields = new LinkedList<>();
        for (IntermediateAsn1Field intermediateAsn1Field : intermediateAsn1Fields) {
            if(this.isFieldExpected(intermediateAsn1Field)) {
                asn1Fields.add(this.translateSingleField(intermediateAsn1Field));
            }
            else {
                throw new TranslatorException("Field is not expected in the given context!");
            }
        }
        return asn1Fields;
    }

    private boolean isFieldExpected(final IntermediateAsn1Field intermediateAsn1Field) {
        // Todo: Check if field is expected by the given context
        return false;
    }

    @Override
    protected Asn1Encodable translateSingleField(final IntermediateAsn1Field intermediateAsn1Field, final FieldTranslator fieldTranslator) throws TranslatorException {
        Asn1Encodable result = super.translateSingleField(intermediateAsn1Field, fieldTranslator);
        // Todo: Depending on the context, create wrappers for the translated field
        return result;
    }

    @Override
    protected List<Asn1Encodable> translateChildren(final List<IntermediateAsn1Field> children) throws TranslatorException {
        ContextBasedTranslator contextBasedTranslator = new ContextBasedTranslator(null /* todo */);
        return contextBasedTranslator.translate(children);
    }
}
