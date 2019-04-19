package de.rub.nds.asn1.translators.contextbasedtranslator.context.defaultcontexts;

import de.rub.nds.asn1.parser.IntermediateAsn1Field;
import de.rub.nds.asn1.translators.contextbasedtranslator.context.AnyContextItem;
import de.rub.nds.asn1.translators.contextbasedtranslator.context.Context;
import de.rub.nds.asn1.translators.contextbasedtranslator.context.ContextItem;

import java.util.List;

public class SimpleAsn1ParserContext extends Context {

    private static final ContextItem[] contextItems = new ContextItem[]{
        new AnyContextItem(false, false)
    };

    public SimpleAsn1ParserContext() {
        super(contextItems);
    }

    /**
     * SimpleAsn1ParserContext has no derived contexts. Hence, an instance of this context is returned.
     *
     * @param intermediateAsn1Fields A list of the IntermediateAsn1Fields corresponding to this context.
     * @return This SimpleAsn1ParserContext object.
     */
    public Context detectSpecificContext(List<IntermediateAsn1Field> intermediateAsn1Fields) {
        return this;
    }
}
