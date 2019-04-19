package de.rub.nds.asn1.translators.contextbasedtranslator.context;

import de.rub.nds.asn1.parser.IntermediateAsn1Field;

import java.util.List;

public abstract class ContextDetector {

    /**
     * Detects the context depending on a list of IntermediateAsn1Fields.
     *
     * @param intermediateAsn1Fields
     * @return The detected context or null, if no context could be detected.
     */
    public abstract Context detectContext(List<IntermediateAsn1Field> intermediateAsn1Fields);
}
