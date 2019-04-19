package de.rub.nds.asn1.translators.contextbasedtranslator.context;

import de.rub.nds.asn1.parser.IntermediateAsn1Field;

import java.util.Iterator;
import java.util.List;

public abstract class Context implements Iterator<ContextItem> {

    private final ContextItem[] contextItems;

    private int nextContextItemPointer = 0;

    protected Context(final ContextItem[] contextItems) {
        this.contextItems = contextItems;
    }

    /**
     * @return True, if another ContextItem is available for this context.
     */
    @Override
    public boolean hasNext() {
        return nextContextItemPointer < contextItems.length;
    }

    /**
     * @return The next ContextItem if available. null, otherwise.
     */
    @Override
    public ContextItem next() {
        ContextItem contextItem = null;
        if (this.hasNext()) {
            contextItem = this.contextItems[this.nextContextItemPointer];
            if (contextItem.isConsumable()) {
                this.nextContextItemPointer++;
            }
        }
        return contextItem;
    }

    /**
     * Increases the next item pointer regardless of whether or not the current ContextItem has been consumed.
     */
    public void consumeCurrent() {
        this.nextContextItemPointer++;
    }

    /**
     * Resets the iterator.
     */
    public void resetIterator() {
        this.nextContextItemPointer = 0;
    }

    /**
     * Detects a specific context based on this context. For example, the extension context is able to detect specific
     * extensions.
     *
     * @param intermediateAsn1Fields A list of the IntermediateAsn1Fields corresponding to this context.
     * @return The detected sub-context or this context's instance, if no context could be detected.
     */
    public abstract Context detectSpecificContext(List<IntermediateAsn1Field> intermediateAsn1Fields);
}
