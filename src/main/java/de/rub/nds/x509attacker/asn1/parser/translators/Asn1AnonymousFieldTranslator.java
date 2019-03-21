package de.rub.nds.x509attacker.asn1.parser.translators;

import de.rub.nds.x509attacker.asn1.model.Asn1AnonymousField;
import de.rub.nds.x509attacker.asn1.model.Asn1Field;
import de.rub.nds.x509attacker.asn1.parser.StructureParser;

public class Asn1AnonymousFieldTranslator extends Translator {

    @Override
    public Asn1Field translatePrototype(final StructureParser.FieldPrototype fieldPrototype, final StructureParser.FieldPrototype parentPrototype) {
        Asn1AnonymousField field = new Asn1AnonymousField();
        field.setAsn1TagClass(fieldPrototype.tagClass.toString());
        field.setAsn1IsConstructed(fieldPrototype.isConstructed);
        field.setAsn1TagNumber(fieldPrototype.tagNumber);
        field.setAsn1Length(fieldPrototype.length);
        field.setAsn1Content(fieldPrototype.content);
        return field;
    }

    @Override
    public byte[] decodeContent(final byte[] content) {
        return content;
    }
}
