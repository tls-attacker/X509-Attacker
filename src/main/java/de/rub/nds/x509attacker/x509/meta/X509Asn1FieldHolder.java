package de.rub.nds.x509attacker.x509.meta;

import de.rub.nds.x509attacker.asn1.model.Asn1RawField;

import java.util.List;

public interface X509Asn1FieldHolder {
    List<Asn1RawField> getFields();

    void clearFields();

    <T extends Asn1RawField> T findField(final Class<T> type);

    <T extends Asn1RawField> T findField(final int pos, final Class<T> type);

    <T extends Asn1RawField> List<T> findAllFields(final Class<T> type);

    Asn1RawField getFieldAtPos(final int pos);

    <T extends Asn1RawField> int countFieldOccurrences(final Class<T> type);
}
