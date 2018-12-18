package de.rub.nds.x509attacker.x509.model.extensions.subjectinformationaccess;

import de.rub.nds.x509attacker.x509.model.defaultvalueholders.Asn1SequenceValueHolder;

public class AccessDescription extends Asn1SequenceValueHolder {

    public AccessDescription() {
        super();
    }

    // Todo: Does this create a conflict with authorityinformationaccess/AccessDescription? Yes it does.
}
