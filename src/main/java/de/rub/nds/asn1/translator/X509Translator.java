
package de.rub.nds.asn1.translator;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.Asn1Field;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translator.fieldtranslators.FieldTranslator;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import de.rub.nds.asn1.translator.Asn1Translator;
import java.util.LinkedList;
import java.util.List;


public abstract class X509Translator {
    
    
    public static <T extends Asn1Encodable> Asn1Encodable translateSingleIntermediateField(final IntermediateAsn1Field intermediateAsn1Field, Class<? extends FieldTranslator<T>> fieldTranslatorClass, final String identifier, final String type) {

        FieldTranslator<? extends Asn1Encodable> fieldTranslator = invokeFieldTranslator(fieldTranslatorClass, intermediateAsn1Field);
        Asn1Encodable result = fieldTranslator.translate(identifier, type);
        return result;
    }
    
    // TranslateSingleIntermediate(,,, wie oben, implicit Flag)
    public static <T extends Asn1Encodable> Asn1Encodable translateSingleIntermediateField(final boolean implicit, final IntermediateAsn1Field intermediateAsn1Field, Class<? extends FieldTranslator<T>> fieldTranslatorClass, final String identifier, final String type) {

        Asn1Encodable result = translateSingleIntermediateField(intermediateAsn1Field, fieldTranslatorClass, identifier, type);
        if(implicit == true && result instanceof Asn1Field) {
            ((Asn1Field) result).setTagClass(intermediateAsn1Field.getTagClass());
            ((Asn1Field) result).setTagNumber(intermediateAsn1Field.getTagNumber());
        }
        return result;
    }
    
    //Fallback Methode, falls Asn1Field Klasse nicht bekannt, wird der Asn1Translator mit dem ParseNativeTypesContext genutzt.
    public static <T extends Asn1Encodable> Asn1Encodable translateSingleIntermediateField(final IntermediateAsn1Field intermediateAsn1Field, final String identifier, final String type) {
        List<IntermediateAsn1Field> intermediateAsn1Fields = new LinkedList<>();
        intermediateAsn1Fields.add(intermediateAsn1Field);
        Asn1Translator asn1Translator = new Asn1Translator(ParseNativeTypesContext.NAME, intermediateAsn1Fields, false);
        Asn1Encodable asn1Encodable = asn1Translator.translate().get(0);
        asn1Encodable.setIdentifier(identifier);
        asn1Encodable.setType(type);
        return asn1Encodable;
    }
    
    
    private static <T extends Asn1Encodable> FieldTranslator<T> invokeFieldTranslator(Class<? extends FieldTranslator<T>> fieldTranslatorClass, final IntermediateAsn1Field intermediateAsn1Field) {
        try {
            Constructor<? extends FieldTranslator<T>> constructor = fieldTranslatorClass.getDeclaredConstructor(IntermediateAsn1Field.class);
            return constructor.newInstance(intermediateAsn1Field);
        } catch(NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
            throw new RuntimeException(e);
        }
    }
}
