package de.rub.nds.x509attacker.asn1.parser.converters;

import de.rub.nds.x509attacker.asn1.model.Asn1RawField;
import de.rub.nds.x509attacker.asn1.parser.StructureParser;

import java.util.List;

public abstract class Converter {

    private final List<StructureParser.FieldPrototype> fieldPrototypes;
    private int fieldPrototypePointer = 0;

    /**
     * Concstructor for abstract Converter class. Takes a list as input since a Converter is supposed to (1) convert a
     * single field, and (2) convert multiple independent fields (e.g. the content of ASN.1 sequences, sets, etc).
     *
     * @param fieldPrototypes List of field prototypes which are then used to create native ASN.1 types.
     */
    public Converter(final List<StructureParser.FieldPrototype> fieldPrototypes) {
        this.fieldPrototypes = fieldPrototypes;
    }

    /**
     * Checks whether or not another field prototype is available.
     *
     * @return True, if another field prototype is available. False otherwise.
     */
    protected boolean hasNextFieldPrototype() {
        return this.fieldPrototypePointer < this.fieldPrototypes.size();
    }

    /**
     * Fetch the next field prototype from the prototype list.
     *
     * @return Returns the next field prototype from the field prototype list.
     * @throws ConverterException Thrown, when no more field prototypes are available. Use hasNextFieldPrototype() to
     *                            check if more field prototypes are available to prevent an exception from being
     *                            thrown.
     */
    protected StructureParser.FieldPrototype getNextFieldPrototype() throws ConverterException {
        if (fieldPrototypePointer < this.fieldPrototypes.size()) {
            StructureParser.FieldPrototype fieldPrototype = this.fieldPrototypes.get(this.fieldPrototypePointer);
            this.fieldPrototypePointer++;
            return fieldPrototype;
        } else {
            throw new ConverterException("No more field prototypes available!");
        }
    }

    /**
     * Converts the field prototypes to native ASN.1 types. Conversion rules depend on the specific converter.
     *
     * @return A list of native ASN.1 types. Each list entry represents a converted field prototype.
     */
    public abstract List<Asn1RawField> convert() throws ConverterException;
}
