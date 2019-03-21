package de.rub.nds.x509attacker.asn1.parser.converters;

import de.rub.nds.x509attacker.asn1.model.Asn1Field;
import de.rub.nds.x509attacker.asn1.model.Asn1RawField;
import de.rub.nds.x509attacker.asn1.parser.ContentDecoderLookupTable;
import de.rub.nds.x509attacker.asn1.parser.StructureParser;
import de.rub.nds.x509attacker.asn1.parser.translators.Translator;

import java.util.LinkedList;
import java.util.List;

public class BasicConverter extends Converter {

    private final StructureParser.FieldPrototype parent;

    /**
     * Creates a basic converter which translates the given field prototypes to their corresponding native ASN.1 types.
     *
     * @param parent          The parent prototype. If the list elements are root elements, parent may be null.
     * @param fieldPrototypes A list containing the field prototypes which are to be converted.
     */
    public BasicConverter(final StructureParser.FieldPrototype parent, final List<StructureParser.FieldPrototype> fieldPrototypes) {
        super(fieldPrototypes);
        this.parent = parent;
    }

    /**
     * Converts the field prototypes to native ASN.1 types without any context information. Implicit and unknown field
     * types are converted to Asn1AnonymousField.
     *
     * @return A list of native ASN.1 types. Each list entry represents a converted field prototype.
     */
    public List<Asn1RawField> convert() throws ConverterException {
        final List<Asn1RawField> resultList = new LinkedList<>();
        while (this.hasNextFieldPrototype()) {
            StructureParser.FieldPrototype fieldPrototype = this.getNextFieldPrototype();
            Translator translator = ContentDecoderLookupTable.findTranslator(fieldPrototype);
            Asn1Field field = translator.translatePrototype(fieldPrototype, this.parent);
            resultList.add(field);
        }
        return resultList;
    }
}
