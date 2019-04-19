package de.rub.nds.asn1.translators.contextbasedtranslator.context;

import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translators.TranslatorException;
import de.rub.nds.asn1.translators.typetranslators.Asn1FieldTranslator;
import de.rub.nds.asn1.translators.typetranslators.TypeTranslator;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

public class ContextItem {

    protected static final int DEFAULT_MATCH_MIN_SCORE = 3;

    private final int matchMinScore;

    private final boolean isOptional;

    private final boolean isConsumable;

    private final ContextItemOption[] contextItemOptions;

    private final Class<? extends TypeTranslator> defaultTypeTranslator;

    public ContextItem(final boolean isOptional, final boolean isConsumable, final ContextItemOption[] contextItemOptions) {
        this(isOptional, isConsumable, contextItemOptions, DEFAULT_MATCH_MIN_SCORE);
    }

    protected ContextItem(final boolean isOptional, final boolean isConsumable, final ContextItemOption[] contextItemOptions, final int matchMinScore) {
        this(isOptional, isConsumable, contextItemOptions, matchMinScore, Asn1FieldTranslator.class);
    }

    protected ContextItem(final boolean isOptional, final boolean isConsumable, final ContextItemOption[] contextItemOptions, final int matchMinScore, final Class<? extends TypeTranslator> defaultTypeTranslator) {
        this.isOptional = isOptional;
        this.isConsumable = isConsumable;
        this.contextItemOptions = contextItemOptions;
        if (matchMinScore >= 0) {
            this.matchMinScore = matchMinScore;
        } else {
            this.matchMinScore = 0;
        }
        this.defaultTypeTranslator = defaultTypeTranslator;
    }

    /**
     * @return True, if this ContextItem is optional.
     */
    public boolean isOptional() {
        return isOptional;
    }

    /**
     * @return True, if the ContextItem is consumed. False, if this ContextItem cannot be consumed.
     */
    public boolean isConsumable() {
        return isConsumable;
    }

    /**
     * @return True, if this ContextItem has a default TypeTranslator.
     */
    public boolean hasDefaultTypeTranslator() {
        return this.defaultTypeTranslator != null;
    }

    /**
     * @param intermediateAsn1Field The IntermediateAsn1Field to be translated.
     * @return True, if a translator is available for the specified IntermediateAsn1Field.
     */
    public boolean hasMatchingTranslator(final IntermediateAsn1Field intermediateAsn1Field) {
        boolean result = false;
        for (ContextItemOption contextItemOption : contextItemOptions) {
            if (this.computeScore(intermediateAsn1Field, contextItemOption) >= matchMinScore) {
                result = true;
                break;
            }
        }
        return result;
    }

    /**
     * @param intermediateAsn1Field The IntermediateAsn1Field to be translated.
     * @return Returns the TypeTranslator for the given IntermediateAsn1Field.
     * @throws TranslatorException
     */
    public TypeTranslator getTypeTranslator(final IntermediateAsn1Field intermediateAsn1Field) throws TranslatorException {
        TypeTranslator typeTranslator = null;
        if (this.hasMatchingTranslator(intermediateAsn1Field)) {
            ContextItemOption bestContextItemOption = null;
            int maxScore = 0;
            for (ContextItemOption contextItemOption : contextItemOptions) {
                int score = this.computeScore(intermediateAsn1Field, contextItemOption);
                if (score > maxScore) {
                    bestContextItemOption = contextItemOption;
                    maxScore = score;
                }
            }
            typeTranslator = this.invokeNewTypeTranslator(bestContextItemOption.typeTranslatorClass, intermediateAsn1Field);
        } else {
            if (this.defaultTypeTranslator != null) {
                typeTranslator = this.invokeNewTypeTranslator(this.defaultTypeTranslator, intermediateAsn1Field);
            } else {
                throw new TranslatorException("IntermediateAsn1Field cannot be translated since there is no matching TypeTranslator available in this context!");
            }
        }
        return typeTranslator;
    }

    private <T extends TypeTranslator> T invokeNewTypeTranslator(final Class<T> typeTranslatorClass, final IntermediateAsn1Field intermediateAsn1Field) throws TranslatorException {
        T typeTranslator = null;
        try {
            Constructor<T> constructor = typeTranslatorClass.getDeclaredConstructor(IntermediateAsn1Field.class);
            typeTranslator = constructor.newInstance(intermediateAsn1Field);
        } catch (NoSuchMethodException e) {
            throw new TranslatorException(e);
        } catch (InstantiationException e) {
            throw new TranslatorException(e);
        } catch (IllegalAccessException e) {
            throw new TranslatorException(e);
        } catch (InvocationTargetException e) {
            throw new TranslatorException(e);
        }
        return typeTranslator;
    }

    /**
     * Computes a match score for a specific IntermediateAsn1Field and ContextItemOption.
     *
     * @param intermediateAsn1Field
     * @param contextItemOption
     * @return The match score.
     */
    protected int computeScore(final IntermediateAsn1Field intermediateAsn1Field, final ContextItemOption contextItemOption) {
        int score = 0;
        if (intermediateAsn1Field.getTagClass() == contextItemOption.tagClass) {
            score++;
            if (intermediateAsn1Field.isConstructed() == contextItemOption.isConstructed) {
                score++;
                if (intermediateAsn1Field.getTagNumber() == contextItemOption.tagNumber) {
                    score++;
                    if (intermediateAsn1Field.containsChildren() == contextItemOption.hasChildren) {
                        score++;
                    }
                }
            }
        }
        return score;
    }
}
