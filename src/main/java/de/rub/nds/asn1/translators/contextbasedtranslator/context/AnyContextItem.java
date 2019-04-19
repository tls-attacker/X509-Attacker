package de.rub.nds.asn1.translators.contextbasedtranslator.context;

public final class AnyContextItem extends ContextItem {

    private static final ContextItemOption[] contextItemOptions = new ContextItemOption[] {
        // Todo: A list of all type translators for native ASN.1 types
    };

    public AnyContextItem(final boolean isOptional, final boolean isConsumed) {
        super(isOptional, isConsumed, contextItemOptions);
    }
}
