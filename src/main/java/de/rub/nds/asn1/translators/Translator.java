package de.rub.nds.asn1.translators;

import de.rub.nds.asn1.model.Asn1Encodable;
import de.rub.nds.asn1.parser.IntermediateAsn1Field;

import java.util.List;

public abstract class Translator {

    /**
     * Translates a list of IntermediateAsn1Field into a list Asn1Encoable. The latter may represent complex ASN.1
     * structures.
     *
     * @param intermediateAsn1Fields
     * @return
     */
    public abstract List<Asn1Encodable> translate(final List<IntermediateAsn1Field> intermediateAsn1Fields) throws TranslatorException;
}
