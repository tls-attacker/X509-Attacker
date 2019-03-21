package de.rub.nds.x509attacker.asn1.parser.translators;

import de.rub.nds.x509attacker.asn1.model.Asn1Field;
import de.rub.nds.x509attacker.asn1.parser.StructureParser;

/**
 * Translators contain all logic to transform parse ASN.1 structures and translate them into native ASN.1 types.
 */
public abstract class Translator {

    /**
     * Translates the given field prototype to a native ASN.1 type. For some native ASN.1 types, the parent element may
     * be required to generate a valid ASN.1 structure in XML.
     *
     * @param fieldPrototype  The field prototype to be converted.
     * @param parentPrototype The parent's field prototype.
     * @return Returns the corresponding native ASN.1 type.
     */
    public abstract Asn1Field translatePrototype(final StructureParser.FieldPrototype fieldPrototype, final StructureParser.FieldPrototype parentPrototype);

    /**
     * A type-specific method to decode the content for further processing.
     *
     * @param content The raw content which is to be deocded.
     * @return Returns the decoded content.
     */
    public abstract byte[] decodeContent(final byte[] content);
}
