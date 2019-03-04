package de.rub.nds.x509attacker.x509.model.types.subjectinformationaccess;

import de.rub.nds.x509attacker.x509.model.x509asn1types.X509Asn1Sequence;

public class AccessDescription extends X509Asn1Sequence {

    public AccessDescription() {
        super();
    }

    // Todo: Does this create a conflict with authorityinformationaccess/AccessDescription? Yes it does.
}
