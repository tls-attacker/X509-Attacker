package de.rub.nds.x509attacker.x509.model.types.subjectinformationaccess;

import de.rub.nds.x509attacker.x509.model.asn1types.Asn1SequenceValueHolder;

public class AccessDescription extends Asn1SequenceValueHolder {

    public AccessDescription() {
        super();
    }

    // Todo: Does this create a conflict with authorityinformationaccess/AccessDescription? Yes it does.
}
