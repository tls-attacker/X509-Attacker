package de.rub.nds.x509attacker.x509.fieldmeta;

import de.rub.nds.x509attacker.asn1.model.Asn1RawField;

import java.util.List;

public interface X509Asn1ValueHolder {
    List<Asn1RawField> getValues();
}
