package de.rub.nds.asn1.translators.contextbasedtranslator.context;

import de.rub.nds.asn1.translators.typetranslators.TypeTranslator;

public class ContextItemOption<T extends TypeTranslator> {

    public final int tagClass;

    public final boolean isConstructed;

    public final int tagNumber;

    public final boolean hasChildren;

    public final Context subContext;

    public final Class<T> typeTranslatorClass;

    public ContextItemOption(final int tagClass, final boolean isConstructed, final int tagNumber, final boolean hasChildren, final Context subContext, final Class<T> typeTranslatorClass) {
        this.tagClass = tagClass;
        this.isConstructed = isConstructed;
        this.tagNumber = tagNumber;
        this.hasChildren = hasChildren;
        this.subContext = subContext;
        this.typeTranslatorClass = typeTranslatorClass;
    }
}
