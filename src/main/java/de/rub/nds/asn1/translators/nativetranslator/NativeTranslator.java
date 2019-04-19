package de.rub.nds.asn1.translators.nativetranslator;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1FieldContainer;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translators.Translator;
import de.rub.nds.asn1.translators.TranslatorException;
import de.rub.nds.asn1.translators.nativetranslator.fieldtranslators.FieldTranslator;

import java.util.LinkedList;
import java.util.List;

public class NativeTranslator extends Translator {

    /**
     * Translates the given structure of IntermediateAsn1Field into a structure of native ASN.1 types. This translator does
     * not take any context information into account. Hence, implicit types will not be converted to native types, but
     * is represented as an instance of Asn1Field instead.
     *
     * @param intermediateAsn1Fields A list of IntermediateAsn1Field to be converted into a structure of native ASN.1 types.
     * @return A structure of native ASN.1 types.
     */
    @Override
    public List<Asn1Encodable> translate(final List<IntermediateAsn1Field> intermediateAsn1Fields) throws TranslatorException {
        List<Asn1Encodable> asn1Fields = new LinkedList<>();
        for (IntermediateAsn1Field intermediateAsn1Field : intermediateAsn1Fields) {
            asn1Fields.add(this.translateSingleField(intermediateAsn1Field));
        }
        return asn1Fields;
    }

    /**
     * Translates the given IntermediateAsn1Field to a native ASN.1 type by determining the type corresponding to the
     * field's identifier.
     *
     * @param intermediateAsn1Field
     * @return
     */
    protected Asn1Encodable translateSingleField(final IntermediateAsn1Field intermediateAsn1Field) throws TranslatorException {
        int tagClass = intermediateAsn1Field.getTagClass();
        boolean isConstructed = intermediateAsn1Field.isConstructed();
        int tagNumber = intermediateAsn1Field.getTagNumber();
        boolean hasChildren = intermediateAsn1Field.containsChildren();
        FieldTranslator fieldTranslator = FieldTranslator.getFieldTranslator(tagClass, isConstructed, tagNumber, hasChildren);
        return this.translateSingleField(intermediateAsn1Field, fieldTranslator);
    }


    /**
     * Translates the given IntermediateAsn1Field to a native ASN.1 type using the specified FieldTranslator.
     *
     * @param intermediateAsn1Field The IntermediateAsn1Field to be translated.
     * @param fieldTranslator    The FieldTranslator used to translate the IntermediateAsn1Field.
     * @return
     */
    protected Asn1Encodable translateSingleField(final IntermediateAsn1Field intermediateAsn1Field, final FieldTranslator fieldTranslator) throws TranslatorException {
        Asn1Encodable result = fieldTranslator.translateImmediateAsn1Field(intermediateAsn1Field);
        if(result instanceof Asn1FieldContainer) {
            Asn1FieldContainer resultAsContainer = (Asn1FieldContainer) result;
            List<Asn1Encodable> translatedChildren = this.translateChildren(intermediateAsn1Field.getChildren());
            resultAsContainer.setChildren(translatedChildren);
        }
        return result;
    }

    protected List<Asn1Encodable> translateChildren(final List<IntermediateAsn1Field> children) throws TranslatorException {
        NativeTranslator nativeTranslator = new NativeTranslator();
        return nativeTranslator.translate(children);
    }
}
